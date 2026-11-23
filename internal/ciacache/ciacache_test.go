package ciacache

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/cia"
	"homebrew-eshop/internal/cia/ciatest"
)

func TestCache(t *testing.T) {
	ciaBytes := ciatest.Build(ciatest.Spec{TitleID: 0x000400000F800100, Name: "App",
		Contents: []ciatest.Content{{ID: 0, Data: make([]byte, 0x200)}}})
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, _ := zw.Create("App/readme.txt")
	w.Write([]byte("hi"))
	w, _ = zw.Create("App/App.cia")
	w.Write(ciaBytes)
	zw.Close()

	var downloads atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/app.cia", func(w http.ResponseWriter, r *http.Request) { downloads.Add(1); w.Write(ciaBytes) })
	mux.HandleFunc("/app.zip", func(w http.ResponseWriter, r *http.Request) { w.Write(zipBuf.Bytes()) })
	mux.HandleFunc("/notcia", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) })
	var srv *httptest.Server
	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"assets": [{"name": "App.3dsx", "browser_download_url": "` + srv.URL + `/notcia"},
			{"name": "App.zip", "browser_download_url": "` + srv.URL + `/app.zip"}]}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := &Cache{Dir: t.TempDir(), GitHubAPI: srv.URL}
	ctx := context.Background()
	check := func(name string, src catalog.CIASource) {
		t.Helper()
		p, err := c.Path(ctx, &src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		f, _ := os.Open(p)
		defer f.Close()
		if got, err := cia.Parse(f); err != nil || got.TitleID != 0x000400000F800100 {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// Many waiters, one download; then served from the cache.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); check("direct", catalog.CIASource{URL: srv.URL + "/app.cia"}) }()
	}
	wg.Wait()
	check("direct again", catalog.CIASource{URL: srv.URL + "/app.cia"})
	if n := downloads.Load(); n != 1 {
		t.Errorf("%d downloads, want 1", n)
	}

	check("zip", catalog.CIASource{URL: srv.URL + "/app.zip", Member: `^App\.cia`})
	check("release", catalog.CIASource{Repo: "o/r", Asset: `.*\.zip`, Member: `App.cia`})

	if _, err := c.Path(ctx, &catalog.CIASource{URL: srv.URL + "/notcia"}); err == nil {
		t.Error("accepted a non-CIA download")
	}
	if _, err := c.Path(ctx, &catalog.CIASource{URL: srv.URL + "/missing"}); err == nil {
		t.Error("accepted a 404")
	}
	if p, _ := c.Path(ctx, &catalog.CIASource{Path: "/x/local.cia"}); p != "/x/local.cia" {
		t.Errorf("local path changed: %s", p)
	}
}

func TestInfoReadsOnlyTheHead(t *testing.T) {
	ciaBytes := ciatest.Build(ciatest.Spec{TitleID: 0x000400000F800200, Version: 7,
		Contents: []ciatest.Content{{ID: 0, Data: make([]byte, 2<<20)}}}) // bigger than headBytes
	release := make(chan struct{})
	var ranged atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			ranged.Store(true)
			http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(ciaBytes))
			return
		}
		<-release // the full download stays stuck until the test ends
		w.Write(ciaBytes)
	}))
	defer srv.Close()
	defer close(release)

	c := &Cache{Dir: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := c.Info(ctx, &catalog.CIASource{URL: srv.URL + "/a.cia"})
	if err != nil {
		t.Fatal(err)
	}
	if !ranged.Load() || f.TitleID != 0x000400000F800200 || f.TitleVersion != 7 || f.Contents[0].Size != 2<<20 {
		t.Errorf("ranged=%v %016X v%d %+v", ranged.Load(), f.TitleID, f.TitleVersion, f.Contents)
	}
}
