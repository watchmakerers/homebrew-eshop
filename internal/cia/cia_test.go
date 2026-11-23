package cia_test

import (
	"bytes"
	"io"
	"testing"

	"homebrew-eshop/internal/cia"
	"homebrew-eshop/internal/cia/ciatest"
)

func TestParse(t *testing.T) {
	main := bytes.Repeat([]byte{0xAA}, 0x300)
	manual := bytes.Repeat([]byte{0xBB}, 0x200)
	raw := ciatest.Build(ciatest.Spec{
		TitleID: 0x0004000000123400, Version: 0x0410,
		Contents: []ciatest.Content{
			{ID: 0, Index: 0, Encrypted: true, Data: main},
			{ID: 7, Index: 1, Data: make([]byte, 0x100), Missing: true},
			{ID: 3, Index: 2, Data: manual},
		},
		Name: "Puzzle Thing", Long: "Puzzle Thing Deluxe", Author: "Me",
	})
	f, err := cia.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if f.TitleID != 0x0004000000123400 || f.TitleVersion != 0x0410 || len(f.Contents) != 3 {
		t.Fatalf("%016X v%d %d contents", f.TitleID, f.TitleVersion, len(f.Contents))
	}
	if !f.Contents[0].Encrypted() || f.Contents[2].Encrypted() || f.Contents[1].Present() {
		t.Errorf("content flags: %+v", f.Contents)
	}
	for id, want := range map[uint32][]byte{0: main, 3: manual} {
		c, ok := f.Content(id)
		if !ok {
			t.Fatalf("content %d missing", id)
		}
		got, _ := io.ReadAll(f.Reader(c))
		if !bytes.Equal(got, want) {
			t.Errorf("content %d: wrong bytes", id)
		}
	}
	if f.SMDH == nil {
		t.Fatal("no SMDH")
	}
	if got := f.SMDH.Title(1); got != (cia.AppTitle{Short: "Puzzle Thing", Long: "Puzzle Thing Deluxe", Publisher: "Me"}) {
		t.Errorf("title %+v", got)
	}
	if got := f.SMDH.Title(0); got.Short != "Puzzle Thing" { // falls back from Japanese to whatever exists
		t.Errorf("fallback title %+v", got)
	}

	tmd, err := f.CDNTMD()
	if err != nil {
		t.Fatal(err)
	}
	certs, _ := cia.SplitCerts(f.Certs)
	if len(certs) != 3 || certs[2].Name != "CP0000000b" {
		t.Fatalf("certs %+v", certs)
	}
	want := append(append(append([]byte{}, f.TMD...), certs[2].Raw...), certs[0].Raw...)
	if !bytes.Equal(tmd, want) {
		t.Error("CDN tmd isn't TMD + CP + CA")
	}
}

func TestParseRejects(t *testing.T) {
	if _, err := cia.Parse(bytes.NewReader(make([]byte, 0x40))); err == nil {
		t.Error("accepted a short file")
	}
	if _, err := cia.Parse(bytes.NewReader(make([]byte, 0x3000))); err == nil {
		t.Error("accepted a zero header")
	}
	noMeta, err := cia.Parse(bytes.NewReader(ciatest.Build(ciatest.Spec{TitleID: 1})))
	if err != nil || noMeta.SMDH != nil {
		t.Errorf("no-meta CIA: %v %+v", err, noMeta)
	}
}

func TestIcon(t *testing.T) {
	s := &cia.SMDH{LargeIcon: make([]byte, 48*48*2)}
	// Pixel 2 of the second tile is (x=0, y=1) in that tile, i.e. (8, 1); make it pure red (RGB565 0xF800).
	s.LargeIcon[(64+2)*2], s.LargeIcon[(64+2)*2+1] = 0x00, 0xF8
	img := s.Icon()
	if r, g, b, _ := img.At(8, 1).RGBA(); r>>8 != 0xFF || g != 0 || b != 0 {
		t.Errorf("(8,1) = %d %d %d", r>>8, g>>8, b>>8)
	}
	if r, _, _, _ := img.At(9, 0).RGBA(); r != 0 {
		t.Error("red pixel landed in the wrong place")
	}
}
