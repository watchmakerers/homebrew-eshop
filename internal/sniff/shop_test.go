package sniff

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"

	"homebrew-eshop/internal/catalog"
)

func TestShop(t *testing.T) {
	// A source icon server: a 64x32 red PNG.
	icon := image.NewRGBA(image.Rect(0, 0, 64, 32))
	for x := 0; x < 64; x++ {
		for y := 0; y < 32; y++ {
			icon.Set(x, y, color.RGBA{255, 0, 0, 255})
		}
	}
	var pngBuf bytes.Buffer
	png.Encode(&pngBuf, icon)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(pngBuf.Bytes()) }))
	defer src.Close()

	titles := []catalog.Title{
		{Name: "Game A", Author: "a", Categories: []string{"game"}, CIA: &catalog.CIASource{URL: "x"}, IconURL: src.URL + "/a.png", Updated: "2026-03-19 at 21:43 (UTC)"},
		{Name: "App B", Categories: []string{"app"}, CIA: &catalog.CIASource{URL: "y"}},
		{Name: "No CIA", Categories: []string{"game"}},
	}
	shop := &Shop{Titles: func() []catalog.Title { return titles }}

	var dirs struct {
		Directories struct {
			Directory []struct {
				ID      int    `json:"id"`
				Name    string `json:"name"`
				IconURL string `json:"icon_url"`
			} `json:"directory"`
		} `json:"directories"`
	}
	if err := json.Unmarshal(shop.directories("samurai.ctr.shop.pretendo.cc").body, &dirs); err != nil {
		t.Fatal(err)
	}
	d := dirs.Directories.Directory
	if len(d) != 3 || d[0].Name != "All Homebrew" || d[0].IconURL != "https://img.ctr.shop.pretendo.cc/dir/1.jpg" {
		t.Fatalf("directories: %+v", d)
	}

	var dir struct {
		Directory struct {
			Contents struct {
				Content []struct {
					Title struct {
						ID      int    `json:"id"`
						Name    string `json:"name"`
						IconURL string `json:"icon_url"`
						Date    string `json:"release_date_on_eshop"`
					} `json:"title"`
				} `json:"content"`
				Total int `json:"total"`
			} `json:"contents"`
		} `json:"directory"`
	}
	if err := json.Unmarshal(shop.directory("samurai.ctr.shop.pretendo.cc", 1, map[string][]string{"limit": {"1"}}).body, &dir); err != nil {
		t.Fatal(err)
	}
	c := dir.Directory.Contents
	if c.Total != 2 || len(c.Content) != 1 || c.Content[0].Title.Name != "Game A" || c.Content[0].Title.Date != "2026-03-19" {
		t.Fatalf("directory 1 (only installable titles, paged): %+v", c)
	}
	if shop.directory("samurai.ctr.shop.pretendo.cc", 99, nil) != nil {
		t.Fatal("unknown directory answered")
	}

	// The icon comes back as a 128x128 JPEG, red in the middle (64x32 scaled to 128x64, centred on white).
	rep := shop.image("/icon/" + itoa(ShopID(titles[0])) + ".jpg")
	img, err := jpeg.Decode(bytes.NewReader(rep.body))
	if err != nil || img.Bounds().Dx() != 128 || img.Bounds().Dy() != 128 {
		t.Fatalf("icon: %v %v", err, img)
	}
	if r, g, _, _ := img.At(64, 64).RGBA(); r < 0xD000 || g > 0x3000 {
		t.Errorf("icon centre not red: %x %x", r, g)
	}
	if r, g, _, _ := img.At(64, 4).RGBA(); r < 0xF000 || g < 0xF000 {
		t.Errorf("icon letterbox not white")
	}
	// No icon URL: a placeholder, never an error.
	if rep := shop.image("/icon/" + itoa(ShopID(titles[1])) + ".jpg"); rep == nil {
		t.Fatal("missing icon gave no image")
	}
	if rep := shop.image("/dir/2.jpg"); rep == nil {
		t.Fatal("no category icon")
	}
	if shop.image("/../etc/passwd") != nil {
		t.Fatal("bad image path answered")
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
