package sniff

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/cia"
	"homebrew-eshop/internal/cia/ciatest"
)

func TestCDNServesLocalCIA(t *testing.T) {
	const tid = 0x0004000000123400
	content := bytes.Repeat([]byte("0123456789abcdef"), 0x100)
	path := filepath.Join(t.TempDir(), "game.cia")
	os.WriteFile(path, ciatest.Build(ciatest.Spec{TitleID: tid, Version: 16, Name: "Puzzle Thing",
		Contents: []ciatest.Content{{ID: 0x2A, Index: 0, Encrypted: true, Data: content}}}), 0o644)
	titles := []catalog.Title{
		{Name: "Puzzle Thing", TitleID: tid, Backup: true, CIA: &catalog.CIASource{Path: path}},
		{Name: "Some Homebrew", TitleID: 0x000400000F800100, CIA: &catalog.CIASource{URL: "https://x/a.cia"}},
	}
	stubs := &Stubs{Shop: &Shop{Titles: func() []catalog.Title { return titles }}}
	rec, err := NewRecorder(t.TempDir(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://ccs.c.shop.pretendo.cc"+path, nil)
		if len(hdr) == 2 {
			r.Header.Set(hdr[0], hdr[1])
		}
		w := httptest.NewRecorder()
		h := &Handler{Rec: rec, Stubs: stubs, Listener: "http"}
		h.ServeHTTP(w, r)
		return w
	}

	f, _ := os.Open(path)
	defer f.Close()
	parsed, _ := cia.Parse(f)
	wantTMD, _ := parsed.CDNTMD()
	for _, p := range []string{"/ccs/download/0004000000123400/tmd", "/ccs/download/0004000000123400/tmd.16"} {
		if w := get(p); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), wantTMD) {
			t.Errorf("%s: %d, %d bytes", p, w.Code, w.Body.Len())
		}
	}
	if w := get("/ccs/download/0004000000123400/0000002a"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), content) {
		t.Errorf("content: %d, %d bytes", w.Code, w.Body.Len())
	}
	if w := get("/ccs/download/0004000000123400/0000002a", "Range", "bytes=16-31"); w.Code != 206 || w.Body.String() != "0123456789abcdef" {
		t.Errorf("range: %d %q", w.Code, w.Body.String())
	}
	for _, p := range []string{
		"/ccs/download/0004000000123400/tmd.3",     // other version
		"/ccs/download/0004000000123400/00000001",  // no such content
		"/ccs/download/000400000F800100/tmd",       // remote CIA, not served
		"/ccs/download/0004000000123400/../../etc", // junk
	} {
		if w := get(p); w.Code != 404 {
			t.Errorf("%s: %d, want 404", p, w.Code)
		}
	}

	// ec_info reports the exact version and size from the file, and the backup gets its own category.
	shop := stubs.Shop
	var ec struct {
		Info struct {
			Version int   `json:"title_version"`
			Size    int64 `json:"content_size"`
		} `json:"title_ec_info"`
	}
	json.Unmarshal(shop.ecInfo(ShopID(titles[0])).body, &ec)
	if ec.Info.Version != 16 || ec.Info.Size != int64(len(content)) {
		t.Errorf("ec_info %+v", ec.Info)
	}
	dirs := shop.dirs()
	if len(dirs) < 2 || dirs[1].id != backupsDirID || len(dirs[1].titles) != 1 || len(dirs[0].titles) != 1 {
		t.Errorf("dirs %+v", dirs)
	}
}
