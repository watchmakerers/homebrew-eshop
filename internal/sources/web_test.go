package sources

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"homebrew-eshop/internal/cia/ciatest"
)

func ncch(productCode string) []byte {
	b := make([]byte, 0x400)
	copy(b[0x100:], "NCCH")
	copy(b[0x150:], productCode)
	return b
}

func TestWebSource(t *testing.T) {
	game := ciatest.Build(ciatest.Spec{TitleID: 0x0004000000155100, Version: 1024, Name: "YO-KAI WATCH 3", Author: "LEVEL-5",
		Contents: []ciatest.Content{{ID: 0, Index: 0, Data: ncch("CTR-P-BYKJ")}}})
	app := ciatest.Build(ciatest.Spec{TitleID: 0x000400000BA1A700, Name: "Balatro",
		Contents: []ciatest.Content{{ID: 0, Index: 0, Data: ncch("CTR-H-BALA")}}})
	files := map[string][]byte{"/3ds/Yo-kai%20Watch%203.cia": game, "/3ds/homebrew/balatro.cia": app,
		"/3ds/homebrew/balatro.json": []byte(`{"categories":["Games"],"description":"poker"}`)}
	var ranged, full int
	mux := http.NewServeMux()
	mux.HandleFunc("/3ds/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/3ds/": // nginx autoindex style
			w.Write([]byte(`<html><body><h1>Index of /3ds/</h1><a href="../">../</a>
<a href="?C=M;O=A">sort</a><a href="homebrew/">homebrew/</a>
<a href="Yo-kai%20Watch%203.cia">Yo-kai Watch 3.cia</a></body></html>`))
		case "/3ds/homebrew/":
			w.Write([]byte(`<a href='balatro.cia'>balatro.cia</a> <a href=balatro.json>balatro.json</a> <a href="/3ds/">up</a>`))
		default:
			b, ok := files[r.URL.EscapedPath()]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("Range") != "" {
				ranged++
			}
			http.ServeContent(w, r, "f", time.Unix(1700000000, 0), bytes.NewReader(b))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	w := &Web{base: base{name: "home"}, URL: srv.URL + "/3ds/", Depth: 1, Backups: true, client: srv.Client()}
	titles, err := w.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(titles) != 2 {
		t.Fatalf("got %d titles: %+v", len(titles), titles)
	}
	b, y := titles[0], titles[1]
	if y.Name != "YO-KAI WATCH 3" || y.Author != "LEVEL-5" || y.TitleID != 0x0004000000155100 || y.ProductCode != "CTR-P-BYKJ" ||
		y.Version != "v1024" || !y.Backup || y.CIA == nil || !strings.HasSuffix(y.CIA.URL, "/3ds/Yo-kai%20Watch%203.cia") {
		t.Errorf("game: %+v", y)
	}
	if b.Name != "Balatro" || b.TitleID != 0x000400000BA1A700 || b.Description != "poker" || len(b.Categories) != 1 {
		t.Errorf("app with sidecar: %+v", b)
	}

	// Without depth the sub-folder isn't followed.
	w0 := &Web{base: base{name: "home"}, URL: srv.URL + "/3ds/", client: srv.Client()}
	if titles, err := w0.Fetch(context.Background()); err != nil || len(titles) != 1 {
		t.Errorf("depth 0: %d titles, %v", len(titles), err)
	}

	// A second refresh reuses what it read while the files are unchanged: one request per CIA.
	before := ranged
	if _, err := w.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := ranged - before; n != 2 {
		t.Errorf("refresh made %d range requests, want 2", n)
	}

	// A server that ignores Range: titles still listed by file name.
	plain := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			rw.Write([]byte(`<a href="Some%20Game.cia">x</a>`))
			return
		}
		full++
		rw.Write(game)
	}))
	defer plain.Close()
	wp := &Web{base: base{name: "plain"}, URL: plain.URL + "/", client: plain.Client()}
	titles, err = wp.Fetch(context.Background())
	if err != nil || len(titles) != 1 || titles[0].Name != "Some Game" || titles[0].CIA == nil {
		t.Errorf("no-range server: %+v %v", titles, err)
	}
}
