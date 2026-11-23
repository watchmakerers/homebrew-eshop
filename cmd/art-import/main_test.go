package main

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"homebrew-eshop/internal/warc"
)

func TestParseEntries(t *testing.T) {
	xmlBody := `<?xml version="1.0"?><eshop><directories length="1"><directory id="7">
		<name>Test Picks</name><icon_url>https://img.example/dir/7.jpg</icon_url>
		<banner_url>https://img.example/dir/7b.jpg</banner_url></directory></directories></eshop>`
	got := parseEntries([]byte(xmlBody))
	if len(got) != 1 || got[0].Kind != "directory" || got[0].ID != "7" || got[0].Name != "Test Picks" ||
		got[0].Banner != "https://img.example/dir/7b.jpg" {
		t.Errorf("xml: %+v", got)
	}

	jsonBody := `{"title": {"id": 42, "name": "Some App", "title_id": "000400000F800100",
		"icon_url": "https://img.example/t/42/icon", "banner_url": ""}}`
	got = parseEntries([]byte(jsonBody))
	if len(got) != 1 || got[0].Kind != "title" || got[0].ID != "42" || got[0].TitleID != "000400000F800100" {
		t.Errorf("json: %+v", got)
	}

	if norm("https://IMG.example:443/a.jpg?x=1") != "img.example/a.jpg?x=1" || norm("http://img.example/a.jpg") != "img.example/a.jpg" {
		t.Error("norm")
	}
}

// End to end with a made-up crawl: a directory reply, a title reply and their images.
func TestImport(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	pngBytes := func() []byte {
		var b bytes.Buffer
		png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 4, 4)))
		return b.Bytes()
	}()
	var w bytes.Buffer
	w.Write(warc.Record("https://samurai.example/samurai/ws/US/directories", 200, "text/xml",
		[]byte(`<eshop><directories><directory id="7"><name>Test Picks</name><icon_url>http://img.example/d7</icon_url><banner_url>https://img.example/d7b</banner_url></directory></directories></eshop>`)))
	w.Write(warc.Record("https://samurai.example/samurai/ws/US/title/42?_type=json", 200, "application/json",
		[]byte(`{"title": {"id": 42, "name": "Some App", "title_id": "000400000f800100", "icon_url": "https://img.example/t42"}}`)))
	w.Write(warc.Record("https://img.example/d7", 200, "image/png", pngBytes))
	w.Write(warc.Record("https://img.example:443/d7b", 200, "image/png", pngBytes))
	w.Write(warc.Record("https://img.example/t42", 200, "image/png", pngBytes))
	w.Write(warc.Record("https://img.example/unrelated", 200, "image/png", pngBytes))

	dir := t.TempDir()
	in := filepath.Join(dir, "crawl.warc")
	os.WriteFile(in, w.Bytes(), 0o644)
	out := filepath.Join(dir, "inbox")
	cmd := exec.Command("go", "run", ".", "-out", out, in)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	for _, f := range []string{"categories/us-test-picks-7.png", "categories/us-test-picks-7-tile.png", "titles/some-app-000400000F800100-icon.png", "index.html"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Error(err)
		}
	}
	idx, _ := os.ReadFile(filepath.Join(out, "index.html"))
	if !strings.Contains(string(idx), "art/titles/000400000F800100-icon.png") {
		t.Error("index lacks the suggested name")
	}
	n := 0
	filepath.Walk(out, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".png") {
			n++
		}
		return nil
	})
	if n != 3 {
		t.Errorf("%d images saved, want 3 (the unrelated one skipped)", n)
	}
}

// A folder saved by a Wayback downloader: files plus _manifest.jsonl mapping each to its original URL.
func TestImportManifestFolder(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	var pngBuf bytes.Buffer
	png.Encode(&pngBuf, image.NewRGBA(image.Rect(0, 0, 4, 4)))
	dir := t.TempDir()
	in := filepath.Join(dir, "saved")
	write := func(rel string, b []byte) {
		p := filepath.Join(in, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, b, 0o644)
	}
	write("samurai.example/samurai/ws/JP/directories", []byte(`<eshop><directories><directory id="3"><name>Picks</name><banner_url>https://img.example/b3.jpg</banner_url></directory></directories></eshop>`))
	write("img.example/b3.jpg", pngBuf.Bytes())
	write("_manifest.jsonl", []byte(
		`{"original": "https://samurai.example/samurai/ws/JP/directories", "statuscode": "200", "path": "samurai.example/samurai/ws/JP/directories"}`+"\n"+
			`{"original": "https://img.example/b3.jpg", "statuscode": "200", "path": "img.example/b3.jpg"}`+"\n"+
			`{"original": "https://img.example/escape.jpg", "path": "../../etc/passwd"}`+"\n"))
	out := filepath.Join(dir, "inbox")
	if b, err := exec.Command("go", "run", ".", "-out", out, in).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if _, err := os.Stat(filepath.Join(out, "categories/jp-picks-3.png")); err != nil {
		t.Error(err)
	}
}
