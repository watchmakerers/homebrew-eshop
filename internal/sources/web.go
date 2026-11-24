package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/cia"
)

// Web lists the .cia files linked from a web page, such as a home server's directory listing (nginx, Apache,
// Caddy, a NAS file share) or any hand-written page. Each CIA's title ID, version, SMDH name and product code
// are read from the file itself with HTTP Range requests (a few small reads, not a download); a server without
// Range support still works, but its titles are named after the file and have no title ID. A linked
// MyApp.json next to MyApp.cia overrides the metadata, as for local folders.
//
// Depth > 0 also follows links to sub-pages below the start URL (folders in a directory listing), that many
// levels deep. With Backups set the CIAs are the user's own dumps of games they own, like a "backups" folder.
type Web struct {
	base
	URL     string
	Depth   int
	Backups bool
	client  *http.Client

	mu   sync.Mutex
	seen map[string]webEntry // CIA URL → what was read last time, reused while size and date are unchanged
}

type webEntry struct {
	stamp string // size + Last-Modified
	title catalog.Title
}

// maxWebPages caps the crawl, in case a page links to itself under endless different names.
const maxWebPages = 200

var hrefRe = regexp.MustCompile(`(?i)<a\s[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)

func (w *Web) Fetch(ctx context.Context) ([]catalog.Title, error) {
	start, err := url.Parse(w.URL)
	if err != nil || (start.Scheme != "http" && start.Scheme != "https") {
		return nil, fmt.Errorf("source %s: url must be http(s)://", w.name)
	}
	cias, jsons, err := w.crawl(ctx, start)
	if err != nil {
		return nil, err
	}

	out := make([]catalog.Title, len(cias))
	errs := make([]error, len(cias))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, u := range cias {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], errs[i] = w.title(ctx, u, jsons)
		}()
	}
	wg.Wait()
	var titles []catalog.Title
	for i, t := range out {
		if errs[i] != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// One unreadable file shouldn't hide the rest; list it by name, installable as a plain download.
			t = catalog.Title{Name: fileStem(cias[i]), CIA: &catalog.CIASource{URL: cias[i]}, Backup: w.Backups}
		}
		titles = append(titles, t)
	}
	if len(titles) == 0 {
		return nil, fmt.Errorf("source %s: no .cia links on %s", w.name, w.URL)
	}
	sort.Slice(titles, func(i, j int) bool { return titles[i].Name < titles[j].Name })
	return titles, nil
}

// crawl returns every .cia link (and .json sidecar link, keyed by URL) found from start.
func (w *Web) crawl(ctx context.Context, start *url.URL) (cias []string, jsons map[string]bool, err error) {
	prefix := start.Scheme + "://" + start.Host + dirOf(start.Path)
	jsons = map[string]bool{}
	seenCIA := map[string]bool{}
	visited := map[string]bool{}
	type page struct {
		u     *url.URL
		depth int
	}
	queue := []page{{start, 0}}
	for len(queue) > 0 && len(visited) < maxWebPages {
		p := queue[0]
		queue = queue[1:]
		key := p.u.String()
		if visited[key] {
			continue
		}
		visited[key] = true
		body, err := getJSONBody(ctx, w.client, key, nil)
		if err != nil {
			if p.depth == 0 {
				return nil, nil, err
			}
			continue // a broken sub-page shouldn't lose the rest
		}
		for _, m := range hrefRe.FindAllSubmatch(body, -1) {
			ref := html.UnescapeString(string(m[1]) + string(m[2]) + string(m[3]))
			u, err := p.u.Parse(ref)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			u.Fragment = ""
			s := u.String()
			ext := strings.ToLower(path.Ext(u.Path))
			switch {
			case ext == ".cia":
				if !seenCIA[s] {
					seenCIA[s] = true
					cias = append(cias, s)
				}
			case ext == ".json":
				jsons[s] = true
			case p.depth < w.Depth && strings.HasSuffix(u.Path, "/") && u.RawQuery == "" &&
				strings.HasPrefix(s, prefix) && len(s) > len(key) && strings.HasPrefix(s, key):
				// Only folders below the current page: never "../", the parent, or sort links (?C=M;O=A).
				queue = append(queue, page{u, p.depth + 1})
			}
		}
	}
	return cias, jsons, nil
}

func (w *Web) title(ctx context.Context, ciaURL string, jsons map[string]bool) (catalog.Title, error) {
	r := &httpReaderAt{ctx: ctx, client: w.client, url: ciaURL}
	if err := r.open(); err != nil {
		return catalog.Title{}, err
	}
	stem := fileStem(ciaURL)
	t := catalog.Title{Name: stem, CIA: &catalog.CIASource{URL: ciaURL}, Backup: w.Backups}
	if r.size > 0 {
		t.Size = humanSize(r.size)
	}

	stamp := fmt.Sprint(r.size, r.modified)
	w.mu.Lock()
	prev, ok := w.seen[ciaURL]
	w.mu.Unlock()
	if ok && prev.stamp == stamp && r.modified != "" {
		t = prev.title
	} else if r.ranges {
		c, err := cia.Parse(r)
		if err != nil {
			return catalog.Title{}, fmt.Errorf("%s: %w", ciaURL, err)
		}
		t.TitleID, t.ProductCode = c.TitleID, c.ProductCode()
		if c.TitleVersion != 0 {
			t.Version = fmt.Sprintf("v%d", c.TitleVersion)
		}
		if c.SMDH != nil {
			if n := c.SMDH.Title(1, 0); n.Short != "" {
				t.Name, t.Author = n.Short, n.Publisher
				if n.Long != "" && n.Long != n.Short {
					t.Description = n.Long
				}
			}
		}
		w.mu.Lock()
		if w.seen == nil {
			w.seen = map[string]webEntry{}
		}
		w.seen[ciaURL] = webEntry{stamp, t}
		w.mu.Unlock()
	}

	side := strings.TrimSuffix(ciaURL, path.Ext(ciaURL)) + ".json"
	if jsons[side] {
		if data, err := getJSONBody(ctx, w.client, side, nil); err == nil {
			var m localMeta
			if err := json.Unmarshal(data, &m); err != nil {
				return catalog.Title{}, fmt.Errorf("%s: %w", side, err)
			}
			for _, f := range []struct {
				dst *string
				v   string
			}{
				{&t.Name, m.Name}, {&t.Author, m.Author}, {&t.Description, m.Description}, {&t.Version, m.Version},
			} {
				if f.v != "" {
					*f.dst = f.v
				}
			}
			if len(m.Categories) > 0 {
				t.Categories = m.Categories
			}
		}
	}
	return t, nil
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i+1]
	}
	return "/"
}

func fileStem(u string) string {
	p := u
	if pu, err := url.Parse(u); err == nil {
		p = pu.Path
	}
	b := path.Base(p)
	return strings.TrimSuffix(b, path.Ext(b))
}

// httpReaderAt reads a remote file with Range requests, a block at a time (a CIA's header, cert chain,
// ticket and TMD sit together at the start, so a handful of requests covers them).
type httpReaderAt struct {
	ctx      context.Context
	client   *http.Client
	url      string
	size     int64
	modified string
	ranges   bool // the server answered a Range request with 206

	mu     sync.Mutex
	blocks map[int64][]byte
}

const webBlock = 64 << 10

// open asks for the first block, learning the size and whether Range works.
func (r *httpReaderAt) open() error {
	_, err := r.block(0)
	return err
}

func (r *httpReaderAt) block(n int64) ([]byte, error) {
	r.mu.Lock()
	b, ok := r.blocks[n]
	r.mu.Unlock()
	if ok {
		return b, nil
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", n*webBlock, (n+1)*webBlock-1))
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusPartialContent:
		r.ranges = true
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			if i := strings.LastIndex(cr, "/"); i >= 0 {
				r.size, _ = strconv.ParseInt(cr[i+1:], 10, 64)
			}
		}
	case http.StatusOK: // no Range support: the whole file is coming; take only what's asked for
		if n != 0 {
			return nil, errors.New("server ignores Range requests")
		}
		r.size = resp.ContentLength
	case http.StatusRequestedRangeNotSatisfiable:
		return nil, io.EOF
	default:
		return nil, fmt.Errorf("GET %s: %s", r.url, resp.Status)
	}
	r.modified = resp.Header.Get("Last-Modified")
	b, err = io.ReadAll(io.LimitReader(resp.Body, webBlock))
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.blocks == nil {
		r.blocks = map[int64][]byte{}
	}
	r.blocks[n] = b
	r.mu.Unlock()
	return b, nil
}

func (r *httpReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if !r.ranges && off+int64(len(p)) > webBlock {
		return 0, errors.New("server ignores Range requests")
	}
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		if r.size > 0 && pos >= r.size {
			return done, io.EOF
		}
		b, err := r.block(pos / webBlock)
		if err != nil {
			return done, err
		}
		i := int(pos % webBlock)
		if i >= len(b) {
			return done, io.EOF
		}
		done += copy(p[done:], b[i:])
	}
	return done, nil
}
