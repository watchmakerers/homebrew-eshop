package warc

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestEach(t *testing.T) {
	recs := [][]byte{
		[]byte("WARC/1.0\r\nWARC-Type: warcinfo\r\nContent-Length: 5\r\n\r\nhello\r\n\r\n"),
		Record("https://a/x.xml", 200, "text/xml", []byte("<x/>")),
		Record("https://a/i.jpg", 404, "text/plain", []byte("nope")),
	}
	dir := t.TempDir()

	// plain, and gzip with one member per record
	plain := filepath.Join(dir, "a.warc")
	os.WriteFile(plain, bytes.Join(recs, nil), 0o644)
	var gz bytes.Buffer
	for _, r := range recs {
		w := gzip.NewWriter(&gz)
		w.Write(r)
		w.Close()
	}
	zipped := filepath.Join(dir, "a.warc.gz")
	os.WriteFile(zipped, gz.Bytes(), 0o644)

	for _, p := range []string{plain, zipped} {
		var got []string
		err := Each(p, func(r *Response) error {
			got = append(got, r.URI+" "+string(r.Body))
			if r.URI == "https://a/i.jpg" && r.Status != 404 {
				t.Errorf("status %d", r.Status)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if len(got) != 2 || got[0] != "https://a/x.xml <x/>" || got[1] != "https://a/i.jpg nope" {
			t.Errorf("%s: %q", p, got)
		}
	}
}
