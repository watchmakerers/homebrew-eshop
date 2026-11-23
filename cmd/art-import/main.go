// art-import pulls shop artwork out of WARC files you've downloaded (e.g. an ArchiveTeam crawl of the eShop's
// samurai server) into a folder to sort through by hand.
//
//	go run ./cmd/art-import [-out art/inbox] file.warc.gz [more files or folders...]
//
// Pass 1 reads every samurai reply in the files (XML or JSON) and notes which image URL belongs to which
// category ("directory"), title or other entry. Pass 2 saves those images, named after their entry:
//
//	<out>/categories/<region>-<name>-<id>.jpg        top-screen banner (banner_url)
//	<out>/categories/<region>-<name>-<id>-tile.jpg   carousel tile (icon_url)
//	<out>/titles/<name>-<title ID>.jpg / -icon.jpg
//	<out>/other/<kind>-<name>-<id>.jpg / -icon.jpg
//
// and writes <out>/index.html to browse them. Nothing is copied into art/categories or art/titles: move the ones
// you want there yourself, renamed as art/README.md describes.
package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"homebrew-eshop/internal/sniff"
	"homebrew-eshop/internal/warc"
)

// entry is something in a samurai reply that has artwork.
type entry struct {
	Kind    string // directory, title, ... (the element or key it came from)
	ID      string
	Name    string
	TitleID string
	Region  string
	Icon    string // icon_url
	Banner  string // banner_url
}

var regionRe = regexp.MustCompile(`/samurai/ws/([A-Za-z]{2})/`)

func main() {
	out := flag.String("out", "art/inbox", "where to put the images and index.html")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: art-import [-out dir] file.warc[.gz]|folder ...")
		fmt.Fprintln(os.Stderr, "A folder is searched for WARCs; a folder with a _manifest.jsonl (one JSON line per saved file with")
		fmt.Fprintln(os.Stderr, "its original URL and local path, as Wayback Machine downloaders write) is read as saved responses.")
		flag.PrintDefaults()
	}
	flag.Parse()
	files, err := sources(flag.Args())
	if err != nil || len(files) == 0 {
		if err == nil {
			err = fmt.Errorf("no .warc/.warc.gz files or folders with a _manifest.jsonl given")
		}
		fmt.Fprintln(os.Stderr, "art-import:", err)
		flag.Usage()
		os.Exit(2)
	}

	// pass 1: metadata
	entries := map[string]*entry{} // by kind/region/id
	for _, f := range files {
		fmt.Fprintf(os.Stderr, "reading catalog data from %s\n", f)
		err := each(f, func(r *warc.Response) error {
			if r.Status != 200 || !strings.Contains(r.URI, "/samurai/") {
				return nil
			}
			region := ""
			if m := regionRe.FindStringSubmatch(r.URI); m != nil {
				region = strings.ToUpper(m[1])
			}
			for _, e := range parseEntries(r.Body) {
				e.Region = region
				key := e.Kind + "/" + e.Region + "/" + e.ID + "/" + e.Name
				if old := entries[key]; old != nil {
					merge(old, e)
				} else {
					e := e
					entries[key] = &e
				}
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %v (continuing with what was read)\n", err)
		}
	}
	wanted := map[string][]want{} // normalised image URL -> where it goes
	for _, e := range entries {
		base, dir := names(e)
		if e.Banner != "" {
			wanted[norm(e.Banner)] = append(wanted[norm(e.Banner)], want{e, filepath.Join(dir, base), "banner"})
		}
		if e.Icon != "" {
			suffix := "-icon"
			if e.Kind == "directory" {
				suffix = "-tile"
			}
			wanted[norm(e.Icon)] = append(wanted[norm(e.Icon)], want{e, filepath.Join(dir, base+suffix), "icon"})
		}
	}
	fmt.Fprintf(os.Stderr, "found %d entries with %d image links\n", len(entries), len(wanted))
	if len(wanted) == 0 {
		fmt.Fprintln(os.Stderr, "no samurai catalog replies with images in these files")
		os.Exit(1)
	}

	// pass 2: images
	var saved []savedImage
	got := map[string]bool{}
	for _, f := range files {
		fmt.Fprintf(os.Stderr, "extracting images from %s\n", f)
		err := each(f, func(r *warc.Response) error {
			ws := wanted[norm(r.URI)]
			if r.Status != 200 || len(ws) == 0 || got[norm(r.URI)] {
				return nil
			}
			ext := imageExt(r.Body)
			if ext == "" {
				return nil
			}
			got[norm(r.URI)] = true
			for _, w := range ws {
				p := filepath.Join(*out, w.path+ext)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(p, r.Body, 0o644); err != nil {
					return err
				}
				saved = append(saved, savedImage{w, p, r.URI})
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %v (continuing)\n", err)
		}
	}
	if err := writeIndex(*out, saved); err != nil {
		fmt.Fprintln(os.Stderr, "art-import:", err)
		os.Exit(1)
	}
	fmt.Printf("saved %d images (%d of %d linked images were in these files) to %s\nopen %s to browse them\n",
		len(saved), len(got), len(wanted), *out, filepath.Join(*out, "index.html"))
}

type want struct {
	e    *entry
	path string // without extension
	role string // banner or icon
}

type savedImage struct {
	want
	file, url string
}

// sources expands the arguments into WARC files and manifest folders.
func sources(args []string) ([]string, error) {
	var out []string
	isWARC := func(p string) bool {
		p = strings.ToLower(p)
		return strings.HasSuffix(p, ".warc") || strings.HasSuffix(p, ".warc.gz")
	}
	for _, a := range args {
		fi, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			out = append(out, a)
			continue
		}
		if _, err := os.Stat(filepath.Join(a, "_manifest.jsonl")); err == nil {
			out = append(out, a)
			continue
		}
		filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isWARC(p) {
				out = append(out, p)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out, nil
}

// each walks the responses in a WARC file, or in a manifest folder.
func each(src string, fn func(*warc.Response) error) error {
	if fi, err := os.Stat(src); err == nil && fi.IsDir() {
		return eachManifest(src, fn)
	}
	return warc.Each(src, fn)
}

// eachManifest reads <dir>/_manifest.jsonl: lines with "original" (the URL), "path" (relative to dir) and
// optionally "statuscode". Missing files are skipped.
func eachManifest(dir string, fn func(*warc.Response) error) error {
	data, err := os.ReadFile(filepath.Join(dir, "_manifest.jsonl"))
	if err != nil {
		return err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		var row struct {
			Original   string `json:"original"`
			Path       string `json:"path"`
			StatusCode string `json:"statuscode"`
		}
		if json.Unmarshal(line, &row) != nil || row.Original == "" || row.Path == "" {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(row.Path))
		if rel, err := filepath.Rel(root, p); err != nil || strings.HasPrefix(rel, "..") {
			continue // stays inside the folder
		}
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		status := 200
		if n, err := strconv.Atoi(row.StatusCode); err == nil {
			status = n
		}
		if err := fn(&warc.Response{URI: row.Original, Status: status, Body: body}); err != nil {
			return err
		}
	}
	return nil
}

// norm makes URLs comparable: no scheme or default port, lowercase host.
func norm(u string) string {
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil || p.Host == "" {
		return strings.TrimSpace(u)
	}
	host := strings.ToLower(p.Hostname())
	return host + p.EscapedPath() + func() string {
		if p.RawQuery != "" {
			return "?" + p.RawQuery
		}
		return ""
	}()
}

func imageExt(b []byte) string {
	switch http.DetectContentType(b) {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	}
	return ""
}

func names(e *entry) (base, dir string) {
	name := sniff.Slug(e.Name)
	if name == "" {
		name = "unnamed"
	}
	switch e.Kind {
	case "directory":
		return strings.Trim(strings.ToLower(e.Region)+"-"+name+"-"+e.ID, "-"), "categories"
	case "title":
		id := e.TitleID
		if id == "" {
			id = "s" + e.ID
		}
		return name + "-" + strings.ToUpper(id), "titles"
	}
	return strings.Trim(sniff.Slug(e.Kind)+"-"+name+"-"+e.ID, "-"), "other"
}

func merge(dst *entry, src entry) {
	set := func(d *string, s string) {
		if *d == "" {
			*d = s
		}
	}
	set(&dst.TitleID, src.TitleID)
	set(&dst.Icon, src.Icon)
	set(&dst.Banner, src.Banner)
}

// --- reading samurai replies ---

// parseEntries finds every object with an icon_url or banner_url in an XML or JSON reply.
func parseEntries(body []byte) []entry {
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return nil
	}
	if t[0] == '{' || t[0] == '[' {
		var v any
		if json.Unmarshal(t, &v) != nil {
			return nil
		}
		var out []entry
		walkJSON("", v, &out)
		return out
	}
	root, err := parseXML(t)
	if err != nil {
		return nil
	}
	var out []entry
	walkXML(root, &out)
	return out
}

func walkJSON(key string, v any, out *[]entry) {
	switch x := v.(type) {
	case map[string]any:
		icon, _ := x["icon_url"].(string)
		banner, _ := x["banner_url"].(string)
		if icon != "" || banner != "" {
			e := entry{Kind: key, Icon: icon, Banner: banner}
			e.Name, _ = x["name"].(string)
			e.TitleID, _ = x["title_id"].(string)
			if id, ok := x["id"]; ok {
				e.ID = fmt.Sprint(id)
			}
			*out = append(*out, e)
		}
		for k, c := range x {
			walkJSON(k, c, out)
		}
	case []any:
		for _, c := range x {
			walkJSON(key, c, out) // array items take the key they're listed under
		}
	}
}

type node struct {
	name     string
	attrs    map[string]string
	children []*node
	text     strings.Builder
}

func (n *node) child(name string) string {
	for _, c := range n.children {
		if c.name == name {
			return strings.TrimSpace(c.text.String())
		}
	}
	return ""
}

func parseXML(b []byte) (*node, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	root := &node{name: "#root"}
	stack := []*node{root}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return root, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				n.attrs[a.Name.Local] = a.Value
			}
			top := stack[len(stack)-1]
			top.children = append(top.children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			stack[len(stack)-1].text.Write(t)
		}
	}
}

func walkXML(n *node, out *[]entry) {
	icon, banner := n.child("icon_url"), n.child("banner_url")
	if icon != "" || banner != "" {
		e := entry{Kind: n.name, Icon: icon, Banner: banner, Name: n.child("name"), TitleID: n.child("title_id"), ID: n.attrs["id"]}
		if e.ID == "" {
			e.ID = n.child("id")
		}
		*out = append(*out, e)
	}
	for _, c := range n.children {
		walkXML(c, out)
	}
}

// --- index.html ---

func writeIndex(out string, saved []savedImage) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	sort.Slice(saved, func(i, j int) bool { return saved[i].file < saved[j].file })
	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset="utf-8"><title>Imported shop art</title>
<style>body{font:14px system-ui,sans-serif;margin:16px;background:#f4f4f4;color:#222}
h2{margin-top:28px}.grid{display:flex;flex-wrap:wrap;gap:12px}
figure{margin:0;background:#fff;border-radius:8px;padding:8px;width:220px;box-shadow:0 1px 3px #0002}
img{max-width:204px;max-height:140px;display:block;margin:auto}figcaption{font-size:12px;margin-top:6px;word-break:break-all}
code{background:#eee;padding:1px 4px;border-radius:3px}
@media (prefers-color-scheme:dark){body{background:#1b1b1b;color:#ddd}figure{background:#2a2a2a}code{background:#333}}</style>
<h1>Imported shop art</h1>
<p>To use one, move it to <code>art/categories/</code> or <code>art/titles/</code> with the name shown under "use as".</p>`)
	groups := map[string][]savedImage{}
	for _, s := range saved {
		groups[filepath.Base(filepath.Dir(s.file))] = append(groups[filepath.Base(filepath.Dir(s.file))], s)
	}
	for _, g := range []string{"categories", "titles", "other"} {
		if len(groups[g]) == 0 {
			continue
		}
		fmt.Fprintf(&b, "<h2>%s (%d)</h2><div class=grid>", g, len(groups[g]))
		for _, s := range groups[g] {
			rel, _ := filepath.Rel(out, s.file)
			fmt.Fprintf(&b, `<figure><a href="%s"><img loading=lazy src="%s"></a><figcaption><b>%s</b> (%s %s)<br>%s`,
				html.EscapeString(filepath.ToSlash(rel)), html.EscapeString(filepath.ToSlash(rel)),
				html.EscapeString(s.e.Name), html.EscapeString(s.e.Kind), html.EscapeString(s.role), html.EscapeString(s.e.Region))
			if use := useAs(s); use != "" {
				fmt.Fprintf(&b, "<br>use as: <code>%s</code>", html.EscapeString(use))
			}
			fmt.Fprintf(&b, "<br><small>%s</small></figcaption></figure>", html.EscapeString(s.url))
		}
		b.WriteString("</div>")
	}
	return os.WriteFile(filepath.Join(out, "index.html"), []byte(b.String()), 0o644)
}

// useAs suggests the art/ name for an image; categories have no match in our shop's own categories, so they
// only get a placeholder to fill in.
func useAs(s savedImage) string {
	ext := filepath.Ext(s.file)
	switch s.e.Kind {
	case "title":
		if s.e.TitleID == "" {
			return ""
		}
		if s.role == "icon" {
			return "art/titles/" + strings.ToUpper(s.e.TitleID) + "-icon" + ext
		}
		return "art/titles/" + strings.ToUpper(s.e.TitleID) + ext
	case "directory":
		if s.role == "icon" {
			return "art/categories/<category>-tile" + ext
		}
		return "art/categories/<category>" + ext
	}
	return ""
}
