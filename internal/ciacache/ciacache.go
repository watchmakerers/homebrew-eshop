// Package ciacache gets the .cia behind a catalog entry onto this machine so it can be served to the console:
// local files are used as they are, and remote ones (a direct URL or a GitHub release asset, optionally inside a
// .zip) are downloaded once and kept in Dir.
//
// Matching follows Universal-Updater, whose scripts the UniStore source reads: a downloadRelease "file" and an
// extractFile "input" are regular expressions.
package ciacache

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/cia"
)

// MaxDownload caps one download (the biggest homebrew CIAs are a few hundred MB).
const MaxDownload = 1 << 30

type Cache struct {
	Dir         string
	Client      *http.Client // default http.DefaultClient
	GitHubAPI   string       // default https://api.github.com
	GitHubToken string
	MaxAge      time.Duration // a remote CIA older than this is downloaded again (default 24h)

	mu       sync.Mutex
	inflight map[string]*call
	urls     map[string]string // resolved release asset URLs, by cache key
}

type call struct {
	done chan struct{}
	path string
	err  error
}

// Path returns a local file holding the title's CIA, downloading it first if needed. Concurrent calls for the
// same CIA share one download. The download keeps going if ctx ends; only the wait is cut short.
func (c *Cache) Path(ctx context.Context, src *catalog.CIASource) (string, error) {
	if src == nil {
		return "", errors.New("no CIA")
	}
	if src.Path != "" {
		return src.Path, nil
	}
	if src.URL == "" && src.Repo == "" {
		return "", errors.New("CIA source has no URL, repo or path")
	}
	if p, ok := c.Ready(src); ok {
		return p, nil
	}
	key := cacheKey(src)
	file := filepath.Join(c.Dir, key+".cia")

	c.mu.Lock()
	if c.inflight == nil {
		c.inflight = map[string]*call{}
	}
	cl := c.inflight[key]
	if cl == nil {
		cl = &call{done: make(chan struct{})}
		c.inflight[key] = cl
		go func() {
			cl.path, cl.err = c.download(*src, file)
			if cl.err != nil {
				// A stale copy is better than nothing when the source is down.
				if _, err := os.Stat(file); err == nil {
					cl.path, cl.err = file, nil
				}
			}
			c.mu.Lock()
			delete(c.inflight, key)
			c.mu.Unlock()
			close(cl.done)
		}()
	}
	c.mu.Unlock()

	select {
	case <-cl.done:
		return cl.path, cl.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Info reads a CIA's header and TMD (title ID, version, contents) without waiting for the whole file. A remote
// CIA's download starts in the background; meanwhile the first headBytes are fetched with a Range request. CIAs
// inside an archive can't be read that way, so for those Info waits for the download.
func (c *Cache) Info(ctx context.Context, src *catalog.CIASource) (*cia.File, error) {
	if src == nil {
		return nil, errors.New("no CIA")
	}
	if p, ok := c.Ready(src); ok {
		return parseFile(p)
	}
	go c.Path(context.Background(), src) // start (or join) the full download
	if src.Member != "" {
		p, err := c.Path(ctx, src)
		if err != nil {
			return nil, err
		}
		return parseFile(p)
	}
	url, err := c.resolve(ctx, src)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "homebrew-eshop/0.1")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", headBytes-1))
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, headBytes)) // a server ignoring Range is cut off here
	if err != nil {
		return nil, err
	}
	f, err := cia.Parse(bytes.NewReader(head))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return f, nil
}

// headBytes is enough for a CIA's header, cert chain, ticket and TMD (a few KB, more with many contents).
const headBytes = 256 << 10

// Ready returns the local file for src if there is one that doesn't need downloading.
func (c *Cache) Ready(src *catalog.CIASource) (string, bool) {
	if src.Path != "" {
		return src.Path, true
	}
	file := filepath.Join(c.Dir, cacheKey(src)+".cia")
	if fi, err := os.Stat(file); err == nil && time.Since(fi.ModTime()) < c.maxAge() {
		return file, true
	}
	return "", false
}

func (c *Cache) maxAge() time.Duration {
	if c.MaxAge == 0 {
		return 24 * time.Hour
	}
	return c.MaxAge
}

func parseFile(p string) (*cia.File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return cia.Parse(f) // header and TMD are read now; contents aren't read through f later
}

// resolve gives the URL to download: the direct one, or the matching asset of the repo's latest release
// (looked up once per run).
func (c *Cache) resolve(ctx context.Context, src *catalog.CIASource) (string, error) {
	if src.URL != "" {
		return src.URL, nil
	}
	key := cacheKey(src)
	c.mu.Lock()
	u := c.urls[key]
	c.mu.Unlock()
	if u != "" {
		return u, nil
	}
	u, err := c.releaseAsset(ctx, src.Repo, src.Asset)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if c.urls == nil {
		c.urls = map[string]string{}
	}
	c.urls[key] = u
	c.mu.Unlock()
	return u, nil
}

func cacheKey(s *catalog.CIASource) string {
	h := sha256.Sum256([]byte(strings.Join([]string{s.URL, s.Repo, s.Asset, s.Member}, "\x00")))
	return hex.EncodeToString(h[:12])
}

func (c *Cache) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}

func (c *Cache) download(src catalog.CIASource, dst string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return "", err
	}
	url, err := c.resolve(ctx, &src)
	if err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(c.Dir, "dl-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := c.get(ctx, url, tmp); err != nil {
		return "", err
	}

	ciaFile := tmp
	if src.Member != "" {
		out, err := os.CreateTemp(c.Dir, "x-*")
		if err != nil {
			return "", err
		}
		defer os.Remove(out.Name())
		defer out.Close()
		if err := extract(tmp, src.Member, out); err != nil {
			return "", fmt.Errorf("%s: %w", url, err)
		}
		ciaFile = out
	}
	if _, err := cia.Parse(ciaFile); err != nil {
		return "", fmt.Errorf("%s: downloaded file isn't a usable CIA: %w", url, err)
	}
	if err := ciaFile.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(ciaFile.Name(), dst); err != nil {
		return "", err
	}
	return dst, nil
}

func (c *Cache) get(ctx context.Context, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "homebrew-eshop/0.1")
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, MaxDownload+1))
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	if n > MaxDownload {
		return fmt.Errorf("GET %s: over %d bytes", url, MaxDownload)
	}
	return nil
}

// releaseAsset finds the download URL of the asset in repo's latest release whose name matches pattern
// (a regexp, as in Universal-Updater; a plain name or glob also works).
func (c *Cache) releaseAsset(ctx context.Context, repo, pattern string) (string, error) {
	api := strings.TrimSuffix(c.GitHubAPI, "/")
	if api == "" {
		api = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "homebrew-eshop/0.1")
	if c.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.GitHubToken)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s latest release: %s", repo, resp.Status)
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&rel); err != nil {
		return "", err
	}
	for _, a := range rel.Assets {
		if nameMatches(pattern, a.Name) {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("%s: no release asset matches %q", repo, pattern)
}

func nameMatches(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if ok, err := path.Match(pattern, name); err == nil && ok {
		return true
	}
	re, err := regexp.Compile(pattern)
	return err == nil && re.MatchString(name)
}

// extract copies the first .zip member whose path matches pattern to w.
func extract(f *os.File, pattern string, w io.Writer) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return fmt.Errorf("not a .zip (other archive formats aren't supported): %w", err)
	}
	for _, m := range zr.File {
		if m.FileInfo().IsDir() || !(nameMatches(pattern, m.Name) || nameMatches(pattern, path.Base(m.Name))) {
			continue
		}
		rc, err := m.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		n, err := io.Copy(w, io.LimitReader(rc, MaxDownload+1))
		if err != nil {
			return err
		}
		if n > MaxDownload {
			return errors.New("archive member too big")
		}
		return nil
	}
	return fmt.Errorf("no file in the archive matches %q", pattern)
}
