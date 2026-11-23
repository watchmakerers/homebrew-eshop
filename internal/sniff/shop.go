package sniff

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	_ "image/gif" // decoders for source icons
	"image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/image/draw"

	"homebrew-eshop/internal/archive"
	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/ciacache"
)

// Shop turns the merged catalog into what the samurai server shows: categories ("directories"), their title
// lists, and images. Only titles that can be installed (have a CIA) are listed.
type Shop struct {
	Titles   func() []catalog.Title
	CacheDir string // resized images are kept here
	Client   *http.Client
	// CIAs downloads remote CIAs so they can be installed; nil means only CIAs on this machine are installable.
	CIAs *ciacache.Cache
	// ArtDir holds the user's own artwork (see art.go); empty means generated artwork only.
	ArtDir string
	// Archive is a saved copy of Nintendo's 3DS catalog, listed browse-only after the homebrew (archive.go
	// here); nil leaves it out.
	Archive *archive.Index

	mu        sync.Mutex
	images    map[string][]byte
	prepared  map[string]*installInfo       // by catalog key
	byTitleID map[uint64]*catalog.CIASource // which CIA has this title ID inside it
	tickets   map[uint64]*issuedTicket      // tickets handed out by AccountPurchaseTitle, by ticket ID
}

type shopDir struct {
	id     int
	name   string
	titles []catalog.Title
}

var categoryNames = map[string]string{
	"game": "Games", "app": "Apps", "utility": "Utilities", "emulator": "Emulators",
	"save-tool": "Save Tools", "firm": "System Tools", "theme": "Themes",
}

// backupsDirID is the "My Backups" category, shown when a backups source has titles. Its fixed ID keeps the
// homebrew categories' IDs the same whether or not it's there.
const backupsDirID = 100

// dirs lists "All Homebrew" (id 1), "My Backups" when there are any, and then up to 8 homebrew categories,
// biggest first. IDs follow that order, so they stay stable while the catalog's category sizes keep their order.
func (s *Shop) dirs() []shopDir {
	var all, backups []catalog.Title
	byCat := map[string][]catalog.Title{}
	for _, t := range s.Titles() {
		if t.CIA == nil {
			continue
		}
		if t.Backup {
			backups = append(backups, t)
			continue
		}
		all = append(all, t)
		for _, c := range t.Categories {
			byCat[strings.ToLower(c)] = append(byCat[strings.ToLower(c)], t)
		}
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool {
		if len(byCat[cats[i]]) != len(byCat[cats[j]]) {
			return len(byCat[cats[i]]) > len(byCat[cats[j]])
		}
		return cats[i] < cats[j]
	})
	if len(cats) > 8 {
		cats = cats[:8]
	}
	out := []shopDir{{id: 1, name: "All Homebrew", titles: all}}
	if len(backups) > 0 {
		out = append(out, shopDir{id: backupsDirID, name: "My Backups", titles: backups})
	}
	for i, c := range cats {
		name := categoryNames[c]
		if name == "" {
			name = strings.ToUpper(c[:1]) + c[1:]
		}
		out = append(out, shopDir{id: i + 2, name: name, titles: byCat[c]})
	}
	return out
}

// ShopID is the number the shop uses for a title (samurai's title "id"), stable for a given app.
func ShopID(t catalog.Title) int {
	h := fnv.New32a()
	h.Write([]byte(t.Key()))
	return int(h.Sum32()&0x3FFFFFFF) + 1
}

func imgBase(samuraiHost string) string {
	return "https://" + strings.Replace(samuraiHost, "samurai.", "img.", 1)
}

func (s *Shop) directories(samuraiHost string) *stubReply {
	var list []map[string]any
	for _, d := range s.dirs() {
		list = append(list, map[string]any{
			"id": d.id, "index": d.id, "name": d.name, "type": "normal", "standard": true, "new": anyNew(d.titles),
			"icon_url":   fmt.Sprintf("%s/dir/%d.jpg", imgBase(samuraiHost), d.id),
			"icon_width": 128, "icon_height": 96, "banner_url": fmt.Sprintf("%s/dirbanner/%d.jpg", imgBase(samuraiHost), d.id),
		})
	}
	list = append(list, s.archiveDirEntries(samuraiHost)...)
	return jsonReply("samurai directories (catalog)", map[string]any{"directories": map[string]any{
		"directory": list, "length": len(list), "catalog_id": 1,
	}})
}

func (s *Shop) directory(samuraiHost string, id int, q map[string][]string) *stubReply {
	if ad := s.archiveDir(int64(id)); ad != nil {
		return s.archiveDirectory(samuraiHost, ad, q)
	}
	var dir *shopDir
	for _, d := range s.dirs() {
		if d.id == id {
			d := d
			dir = &d
		}
	}
	if dir == nil {
		return nil
	}
	offset, limit := queryInt(q, "offset", 0), queryInt(q, "limit", len(dir.titles))
	page := dir.titles[min(offset, len(dir.titles)):min(offset+max(limit, 0), len(dir.titles))]

	base := imgBase(samuraiHost)
	content := make([]map[string]any, 0, len(page))
	for i, t := range page {
		sid := ShopID(t)
		author := t.Author
		if author == "" {
			author = "Unknown"
		}
		genre := "Homebrew"
		if len(t.Categories) > 0 {
			if n := categoryNames[strings.ToLower(t.Categories[0])]; n != "" {
				genre = n
			}
		}
		content = append(content, map[string]any{
			"index": offset + i + 1,
			"title": map[string]any{
				"id":                    sid,
				"name":                  t.Name,
				"product_code":          fmt.Sprintf("HBR-N-%06X", sid&0xFFFFFF),
				"publisher":             map[string]any{"id": 1, "name": author},
				"display_genre":         genre,
				"release_date_on_eshop": releaseDate(t.Updated),
				"retail_sales":          false, "eshop_sales": true, "demo_available": false,
				"aoc_available": false, "in_app_purchase": false, "new": isNew(&t),
				"icon_url":   fmt.Sprintf("%s/icon/%d.jpg", base, sid),
				"banner_url": fmt.Sprintf("%s/banner/%d.jpg", base, sid),
			},
		})
	}
	return jsonReply(fmt.Sprintf("samurai directory %d (catalog, %d titles)", id, len(page)), map[string]any{"directory": map[string]any{
		"id": dir.id, "name": dir.name,
		"icon_url": fmt.Sprintf("%s/dir/%d.jpg", base, dir.id), "icon_width": 76, "icon_height": 58,
		"banner_url": fmt.Sprintf("%s/dirbanner/%d.jpg", base, dir.id),
		"contents":   map[string]any{"content": content, "length": len(content), "offset": offset, "total": len(dir.titles)},
	}})
}

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)

// newFor is how long after its last update a title shows the "New" ribbon.
const newFor = 30 * 24 * time.Hour

func isNew(t *catalog.Title) bool {
	d := dateRe.FindString(t.Updated)
	if d == "" {
		return false
	}
	when, err := time.Parse("2006-01-02", d)
	return err == nil && time.Since(when) < newFor
}

func anyNew(titles []catalog.Title) bool {
	for i := range titles {
		if isNew(&titles[i]) {
			return true
		}
	}
	return false
}

func releaseDate(updated string) string {
	if d := dateRe.FindString(updated); d != "" {
		return d
	}
	return time.Now().Format("2006-01-02")
}

func queryInt(q map[string][]string, key string, def int) int {
	if v := q[key]; len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// Images: /icon/<shopid>.jpg (128x128), /banner/<shopid>.jpg (400x240), /dir/<id>.jpg (a category's tile,
// 128x96) and /dirbanner/<id>.jpg (its top-screen banner, 400x240). See art.go for where each comes from.
var imagePath = regexp.MustCompile(`^/(icon|banner|dir|dirbanner)/([0-9]+)\.jpg$`)

func (s *Shop) image(path string) *stubReply {
	m := imagePath.FindStringSubmatch(path)
	if m == nil {
		return nil
	}
	kind, id := m[1], m[2]
	n, _ := strconv.Atoi(id)
	if r, ok := s.archiveImage(kind, int64(n)); ok {
		if r == nil {
			w, h := 128, 128
			switch kind {
			case "banner", "dirbanner":
				w, h = 400, 240
			case "dir":
				w, h = 128, 96
			}
			return jpegReply("image archive placeholder", placeholder(w, h))
		}
		return r
	}

	var img image.Image
	var key string
	switch kind {
	case "dir", "dirbanner":
		var d *shopDir
		for _, x := range s.dirs() {
			if x.id == n {
				x := x
				d = &x
			}
		}
		if d == nil {
			return nil
		}
		h := fnv.New32a()
		for _, t := range d.titles[:min(len(d.titles), 4)] {
			h.Write([]byte(t.Key() + t.IconURL + "\n"))
		}
		key = fmt.Sprintf("%s-%s-%08x-%s", kind, id, h.Sum32(), s.artVersion())
		if data := s.cached(key); data != nil {
			return &stubReply{name: "image " + key + " (cached)", contentType: "image/jpeg", body: data}
		}
		slug := Slug(d.name)
		if kind == "dir" {
			if u := s.userArt("categories", slug+"-tile"); u != nil {
				img = fit(u, 128, 96)
			} else {
				img = dirTile(*d, s.icons(d.titles, 4))
			}
		} else {
			if u := s.userArt("categories", slug); u != nil {
				img = fit(u, 400, 240)
			} else {
				img = dirBanner(*d, s.icons(d.titles, 3))
			}
		}
	default:
		t := s.byShopID(n)
		if t == nil {
			return nil
		}
		if a := s.backupArchive(t); a != nil { // the game's original eShop art
			path := a.Icon
			if kind == "banner" {
				path = a.Banner
			}
			if b := archive.ReadImage(path); b != nil {
				return &stubReply{name: "image backup " + id + " (archive)", contentType: "image/jpeg", body: b}
			}
		}
		key = fmt.Sprintf("%s-%s-%s", kind, id, s.artVersion())
		if data := s.cached(key); data != nil {
			return &stubReply{name: "image " + key + " (cached)", contentType: "image/jpeg", body: data}
		}
		if kind == "icon" {
			if icon := s.titleIcon(t); icon != nil {
				img = fit(icon, 128, 128)
			} else {
				img = placeholder(128, 128)
			}
		} else if u := s.userArt("titles", titleArtNames(t, "")...); u != nil {
			img = fit(u, 400, 240)
		} else if b := s.fetch(t.BannerURL); b != nil {
			img = fit(b, 400, 240)
		} else {
			img = titleBanner(t, s.titleIcon(t))
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		return nil
	}
	s.store(key, buf.Bytes())
	return &stubReply{name: "image " + key, contentType: "image/jpeg", body: buf.Bytes()}
}

func (s *Shop) byShopID(n int) *catalog.Title {
	for _, t := range s.Titles() {
		if ShopID(t) == n {
			t := t
			return &t
		}
	}
	return nil
}

// titleIcon is the title's icon at its own size: the user's, the source's, or the one inside its CIA.
func (s *Shop) titleIcon(t *catalog.Title) image.Image {
	if u := s.userArt("titles", titleArtNames(t, "-icon")...); u != nil {
		return u
	}
	if i := s.fetch(t.IconURL); i != nil {
		return i
	}
	return s.ciaIcon(t)
}

// icons returns the icons of the first titles that have one, up to n.
func (s *Shop) icons(titles []catalog.Title, n int) []image.Image {
	var out []image.Image
	for i := 0; i < len(titles) && len(out) < n && i < n*3; i++ {
		t := titles[i]
		if icon := s.titleIcon(&t); icon != nil {
			out = append(out, icon)
		}
	}
	return out
}

// fetchFit downloads an image and fits it into w x h on a white background. A missing or broken source gives a
// plain placeholder, so the shop never shows a broken image.
func (s *Shop) fetchFit(src string, w, h int) image.Image {
	if img := s.fetch(src); img != nil {
		return fit(img, w, h)
	}
	return placeholder(w, h)
}

// fetch downloads and decodes an image; nil if src is empty or anything fails.
func (s *Shop) fetch(src string) image.Image {
	if src == "" {
		return nil
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "homebrew-eshop/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	img, _, err := image.Decode(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil
	}
	return img
}

// fit scales src into w x h, centred on white.
func fit(srcImg image.Image, w, h int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(dst, dst.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	b := srcImg.Bounds()
	scale := min(float64(w)/float64(b.Dx()), float64(h)/float64(b.Dy()))
	sw, sh := max(int(float64(b.Dx())*scale), 1), max(int(float64(b.Dy())*scale), 1)
	at := image.Rect((w-sw)/2, (h-sh)/2, (w-sw)/2+sw, (h-sh)/2+sh)
	draw.CatmullRom.Scale(dst, at, srcImg, b, draw.Over, nil)
	return dst
}

func placeholder(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{0xE4, 0xE7, 0xEB, 0xFF}), image.Point{}, draw.Src)
	return img
}

func (s *Shop) cached(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if data, ok := s.images[key]; ok {
		return data
	}
	if s.CacheDir != "" {
		if data, err := os.ReadFile(filepath.Join(s.CacheDir, key+".jpg")); err == nil {
			if s.images == nil {
				s.images = map[string][]byte{}
			}
			s.images[key] = data
			return data
		}
	}
	return nil
}

func (s *Shop) store(key string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.images == nil {
		s.images = map[string][]byte{}
	}
	s.images[key] = data
	if s.CacheDir != "" && os.MkdirAll(s.CacheDir, 0o755) == nil {
		os.WriteFile(filepath.Join(s.CacheDir, key+".jpg"), data, 0o644)
	}
}
