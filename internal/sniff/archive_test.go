package sniff

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"homebrew-eshop/internal/archive"
	"homebrew-eshop/internal/catalog"
)

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveShop(t *testing.T) {
	root := t.TempDir()
	img := "https://kanzashi-ctr.cdn.nintendo.net/i/"
	ws := filepath.Join(root, "samurai.ctr.shop.nintendo.net", "samurai", "ws")
	writeFile(t, filepath.Join(ws, "US", "contents@x"), []byte(`<?xml version="1.0"?><eshop><contents>`+
		`<content index="1"><title id="50010000000001"><product_code>CTR-N-AKRE</product_code><name>Kirby Test</name>`+
		`<icon_url>`+img+`aaaa.jpg</icon_url><banner_url>`+img+`bbbb.jpg</banner_url>`+
		`<platform device="CTR"><name>Nintendo 3DS Download Only</name></platform><publisher><name>Nintendo</name></publisher>`+
		`<display_genre>Action</display_genre><rating_info><rating_system id="202"><name>ESRB</name></rating_system><rating id="2">`+
		`<icons><icon url="`+img+`eeee1.jpg" type="normal"/></icons><name>E</name><age>6</age></rating>`+
		`<descriptors><descriptor><name>Comic Mischief</name></descriptor></descriptors></rating_info>`+
		`<star_rating_info><score>4.5</score><votes>10</votes><star1>0</star1><star2>0</star2><star3>1</star3><star4>3</star4><star5>6</star5></star_rating_info>`+
		`<release_date_on_eshop>2014-01-02</release_date_on_eshop></title></content>`+
		`<content index="2"><title id="50010000000002"><product_code>CTR-N-UPDE</product_code><name>Some update</name>`+
		`<platform><name>Software Update</name></platform></title></content></contents></eshop>`))
	writeFile(t, filepath.Join(ws, "SI", "directories@y"), []byte(`<eshop><directories>`+
		`<directory id="1094196" type="search"><name>Kirby</name><icon_url>`+img+`cccc.jpg</icon_url><banner_url>`+img+`dddd.jpg</banner_url></directory>`+
		`<directory id="1094214" type="normal"><name>Nintendo Switch</name><icon_url>`+img+`eeee.jpg</icon_url></directory>`+
		`</directories></eshop>`))
	writeFile(t, filepath.Join(ws, "US", "title", "50010000000001"), []byte(`<eshop><title id="50010000000001">`+
		`<product_code>CTR-N-AKRE</product_code><name>Kirby Test</name><description>Line one&lt;BR&gt;Line two</description>`+
		`<screenshots><screenshot><image_url type="upper">`+img+`ffff.jpg</image_url><image_url type="lower">`+img+`9999.jpg</image_url></screenshot></screenshots></title></eshop>`))
	images := filepath.Join(root, "kanzashi-ctr.cdn.nintendo.net", "i")
	writeFile(t, filepath.Join(images, "aaaa.jpg"), []byte("ICON"))
	writeFile(t, filepath.Join(images, "bbbb.jpg"), []byte("BANNER"))
	writeFile(t, filepath.Join(images, "cccc.jpg"), []byte("TILE"))
	writeFile(t, filepath.Join(images, "ffff.jpg"), []byte("TOP"))
	writeFile(t, filepath.Join(images, "eeee1.jpg"), []byte("ESRB-E"))
	writeFile(t, filepath.Join(images, "9999.jpg"), []byte("BOTTOM"))

	x, err := archive.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(x.Titles) != 1 {
		t.Fatalf("titles = %d, want 1 (updates are skipped)", len(x.Titles))
	}
	backup := catalog.Title{Name: "My Kirby", Backup: true, ProductCode: "CTR-P-AKRE", CIA: &catalog.CIASource{Path: "x.cia"}}
	var have []catalog.Title // the user's backups: none yet
	shop := &Shop{Titles: func() []catalog.Title { return have }, Archive: x}
	host := "samurai.ctr.shop.pretendo.cc"

	// Not owned: browse only, sales terminated.
	r := shop.directory(host, 1094196, url.Values{})
	if r == nil || !bytes.Contains(r.body, []byte(`"id":50010000000001`)) || !bytes.Contains(r.body, []byte(`"eshop_sales":false`)) {
		t.Fatalf("archive directory: %v", r)
	}
	page := shop.title(host, 50010000000001)
	if page == nil || !bytes.Contains(page.body, []byte(`Line one\nLine two`)) || !bytes.Contains(page.body, []byte(`"downloadable":false`)) {
		t.Fatalf("archive title page: %s", page.body)
	}
	prices := shop.onlinePrices("US", url.Values{"title[]": {"50010000000001"}})
	if !bytes.Contains(prices.body, []byte(`"sales_termination"`)) {
		t.Errorf("prices: %s", prices.body)
	}
	if shop.find(50010000000001) != nil {
		t.Error("an unowned archive title must not be installable")
	}

	// Owned (a Japanese dump, CTR-P-AKRJ, of the archived American CTR-N-AKRE): on sale, free, installs the backup.
	have = []catalog.Title{{Name: "My JP Kirby", Backup: true, ProductCode: "CTR-P-AKRJ", TitleID: 0x0004000000123400, CIA: &catalog.CIASource{Path: "jp.cia"}}}
	r = shop.directory(host, 1094196, url.Values{})
	if r == nil || !bytes.Contains(r.body, []byte(`"eshop_sales":true`)) {
		t.Fatalf("owned archive directory entry should be on sale: %s", r.body)
	}
	page = shop.title(host, 50010000000001)
	if page == nil || !bytes.Contains(page.body, []byte(`"downloadable":true`)) || !bytes.Contains(page.body, []byte(`"title_id":"0004000000123400"`)) {
		t.Fatalf("owned archive title page: %s", page.body)
	}
	prices = shop.onlinePrices("US", url.Values{"title[]": {"50010000000001"}})
	if !bytes.Contains(prices.body, []byte(`"onsale"`)) {
		t.Errorf("owned prices: %s", prices.body)
	}
	if b := shop.find(50010000000001); b == nil || b.Name != "My JP Kirby" {
		t.Errorf("archive ID should find the backup: %v", b)
	}
	if shop.ecInfo(50010000000001) == nil || shop.prepurchaseInfo("US", 50010000000001) == nil {
		t.Error("ec_info / prepurchase_info should answer for an owned archive title")
	}

	have = []catalog.Title{backup}

	var dirs struct {
		Directories struct {
			Directory []struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"directory"`
		} `json:"directories"`
	}
	json.Unmarshal(shop.directories(host).body, &dirs)
	var names []string
	for _, d := range dirs.Directories.Directory {
		names = append(names, d.Name)
	}
	if got := strings.Join(names, "|"); got != "All Homebrew|My Backups|Kirby|Nintendo eShop Archive" {
		t.Errorf("directories = %s", got)
	}

	page = shop.title(host, 50010000000001)
	for _, want := range []string{`"star_rating_info":{"score":4.5,"star1":0,"star2":0,"star3":1,"star4":3,"star5":6,"votes":10}`,
		`"rating":{"age":6,"icons":{"icon":[{"type":"normal","url":"https://img.ctr.shop.pretendo.cc/rating/50010000000001/0.jpg"}]},"id":2,"name":"E"}`,
		`"rating_system":{"id":202,"name":"ESRB"}`, `"descriptors":{"descriptor":[{"name":"Comic Mischief"}]}`} {
		if !bytes.Contains(page.body, []byte(want)) {
			t.Errorf("title page lacks %s:\n%s", want, page.body)
		}
	}
	if r := shop.image("/rating/50010000000001/0.jpg"); r == nil || string(r.body) != "ESRB-E" {
		t.Errorf("rating icon not served: %v", r)
	}
	if !bytes.Contains(page.body, []byte(`"screenshots":{"screenshot":[{"image_url":[{"type":"upper","value":"https://img.ctr.shop.pretendo.cc/shot/50010000000001/0/upper.jpg"},{"type":"lower"`)) {
		t.Errorf("screenshots missing from title page: %s", page.body)
	}
	if r := shop.image("/shot/50010000000001/0/lower.jpg"); r == nil || string(r.body) != "BOTTOM" {
		t.Errorf("screenshot not served: %v", r)
	}
	if r := shop.image("/banner/50010000000001.jpg"); r == nil || string(r.body) != "BANNER" {
		t.Errorf("archived banner not served as-is: %v", r)
	}
	if r := shop.image("/dir/1094196.jpg"); r == nil || string(r.body) != "TILE" {
		t.Errorf("archived tile not served as-is: %v", r)
	}
	if r := shop.image("/dirbanner/1094196.jpg"); r == nil || len(r.body) < 100 { // not archived: generated
		t.Errorf("missing category banner should be generated")
	}
	// The user's own backup gets the game's original art and description.
	sid := ShopID(backup)
	if r := shop.image("/icon/" + strconv.Itoa(sid) + ".jpg"); r == nil || string(r.body) != "ICON" {
		t.Errorf("backup icon should come from the archive: %v", r)
	}
	if p := shop.title(host, sid); p == nil || !bytes.Contains(p.body, []byte("Line one")) {
		t.Errorf("backup page should use the archived description")
	}
}
