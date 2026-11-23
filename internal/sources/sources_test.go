package sources

import (
	"context"
	"homebrew-eshop/internal/cia/ciatest"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/config"
)

const testStore = `{
  "storeInfo": {"title": "Test", "version": 3},
  "storeContent": [
    {
      "info": {"title": "Direct CIA", "author": "a", "console": ["3DS"], "category": ["game"], "title_ids": [875533],
               "screenshots": [{"description": "s", "url": "https://x/s.png"}]},
      "App.3dsx": {"script": [{"type": "downloadFile", "file": "https://x/App.3dsx", "output": "%3DSX%/App.3dsx"}], "size": "1 KiB"},
      "App.cia": {"script": [
        {"type": "downloadFile", "file": "https://x/App.cia", "output": "/App.cia"},
        {"type": "installCia", "file": "/App.cia"},
        {"type": "deleteFile", "file": "/App.cia"}], "size": "2 MiB"}
    },
    {
      "info": {"title": "Zipped", "console": "3DS", "title_ids": ["0x12345"]},
      "Zipped.zip": [
        {"type": "downloadRelease", "repo": "o/r", "file": "Zipped.zip", "output": "/Zipped.zip"},
        {"type": "extractFile", "file": "/Zipped.zip", "input": "^Zipped.cia", "output": "/tmp.cia"},
        {"type": "move", "old": "/tmp.cia", "new": "sdmc:/Zipped.cia"},
        {"type": "installCia", "file": "/Zipped.cia"}]
    },
    {"info": {"title": "DS only", "console": ["NDS"]}},
    {"info": {"title": "No CIA", "console": ["3DS"]},
     "x.3dsx": {"script": [{"type": "downloadFile", "file": "https://x/x.3dsx", "output": "/x.3dsx"}]}},
    {"info": "broken"}
  ]
}`

func TestParseUniStore(t *testing.T) {
	titles, err := ParseUniStore([]byte(testStore))
	if err != nil {
		t.Fatal(err)
	}
	if len(titles) != 3 {
		t.Fatalf("got %d titles, want 3 (DS-only and broken skipped): %+v", len(titles), titles)
	}
	d := titles[0]
	if d.TitleID != 0x000400000D5C0D00 {
		t.Errorf("title ID %016X", d.TitleID)
	}
	if d.CIA == nil || d.CIA.URL != "https://x/App.cia" || d.Size != "2 MiB" {
		t.Errorf("direct CIA: %+v size %q", d.CIA, d.Size)
	}
	if len(d.Screenshots) != 1 || d.Categories[0] != "game" {
		t.Errorf("metadata: %+v", d)
	}
	z := titles[1]
	want := catalog.CIASource{Repo: "o/r", Asset: "Zipped.zip", Member: "^Zipped.cia"}
	if z.CIA == nil || *z.CIA != want {
		t.Errorf("zipped CIA: %+v", z.CIA)
	}
	if z.TitleID != 0x0004000001234500 {
		t.Errorf("hex string title ID: %016X", z.TitleID)
	}
	if titles[2].CIA != nil {
		t.Errorf("3dsx-only app got a CIA: %+v", titles[2].CIA)
	}
}

func TestAddImages(t *testing.T) {
	titles := []catalog.Title{{Name: "Direct CIA"}, {Name: "Other"}}
	meta := `[{"title": "direct cia", "icon": "https://x/i.png", "image": "https://x/b.png"}, {"title": "Other", "icon": "javascript:x"}]`
	if err := AddImages(titles, []byte(meta)); err != nil {
		t.Fatal(err)
	}
	if titles[0].IconURL != "https://x/i.png" || titles[0].BannerURL != "https://x/b.png" || titles[1].IconURL != "" {
		t.Fatalf("%+v", titles)
	}
}

func TestGitHub(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name": "app", "description": "An app", "owner": {"login": "o"}, "license": {"spdx_id": "MIT"}}`))
	})
	mux.HandleFunc("/repos/o/app/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing token")
		}
		w.Write([]byte(`{"tag_name": "v2", "assets": [
			{"name": "app.3dsx", "browser_download_url": "https://dl/app.3dsx", "size": 10},
			{"name": "app.cia", "browser_download_url": "https://dl/app.cia", "size": 3145728}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	src, err := New(config.Source{Name: "gh", Type: "github", Repo: "o/app", TitleID: "000400000ABCDE00"},
		Options{GitHubAPI: srv.URL, GitHubToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	titles, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := titles[0]
	if got.Name != "app" || got.Author != "o" || got.Version != "v2" || got.License != "mit" ||
		got.TitleID != 0x000400000ABCDE00 || got.CIA.URL != "https://dl/app.cia" || got.Size != "3 MiB" {
		t.Errorf("%+v", got)
	}
}

func fakeCIA(titleID uint64) []byte { return ciatest.Build(ciatest.Spec{TitleID: titleID}) }

func TestBackups(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "dump-0123.cia"), ciatest.Build(ciatest.Spec{
		TitleID: 0x0004000000123400, Version: 1040, Name: "Puzzle Thing", Long: "Puzzle Thing Deluxe", Author: "Some Publisher",
		Contents: []ciatest.Content{{ID: 0, Index: 0, Encrypted: true, Data: make([]byte, 0x400)}},
	}), 0o644)
	src, err := New(config.Source{Name: "mine", Type: "backups", Path: dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	titles, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(titles) != 1 {
		t.Fatalf("%+v", titles)
	}
	got := titles[0]
	if !got.Backup || got.Name != "Puzzle Thing" || got.Author != "Some Publisher" || got.Description != "Puzzle Thing Deluxe" ||
		got.Version != "v1040" || got.TitleID != 0x0004000000123400 {
		t.Errorf("%+v", got)
	}
}

func TestLocal(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Mine.cia"), fakeCIA(0x000400000F800100), 0o644)
	os.WriteFile(filepath.Join(dir, "Mine.json"), []byte(`{"name": "My App", "author": "me"}`), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644)

	titles, err := (&Local{Dir: dir}).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(titles) != 1 || titles[0].Name != "My App" || titles[0].TitleID != 0x000400000F800100 ||
		titles[0].CIA.Path != filepath.Join(dir, "Mine.cia") {
		t.Fatalf("%+v", titles)
	}
}
