package sniff

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"homebrew-eshop/internal/archive"
	"homebrew-eshop/internal/catalog"
)

func TestSearch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root+"/samurai.ctr.shop.nintendo.net/samurai/ws/US/contents@x", []byte(`<eshop><contents>`+
		`<content index="1"><title id="50010000000001"><product_code>CTR-N-AKRE</product_code><name>Pokémon™ Picross</name><publisher><name>Nintendo</name></publisher><release_date_on_eshop>2015-12-03</release_date_on_eshop></title></content>`+
		`<content index="2"><title id="50010000000002"><product_code>CTR-N-AZZE</product_code><name>Other Game</name><publisher><name>Pokémon Co</name></publisher><release_date_on_eshop>2016-01-01</release_date_on_eshop></title></content>`+
		`</contents></eshop>`))
	x, err := archive.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	titles := []catalog.Title{
		{Name: "PKSM", Author: "FlagBrew", Description: "Pokemon save manager", CIA: &catalog.CIASource{URL: "x"}},
		{Name: "Checkpoint", CIA: &catalog.CIASource{URL: "y"}},
	}
	shop := &Shop{Titles: func() []catalog.Title { return titles }, Archive: x}
	var v struct {
		Contents struct {
			Total   int `json:"total"`
			Content []struct {
				Title struct {
					Name string `json:"name"`
				} `json:"title"`
			} `json:"content"`
		} `json:"contents"`
	}
	get := func(q url.Values) []string {
		t.Helper()
		v.Contents.Content = nil
		if err := json.Unmarshal(shop.search("samurai.ctr.shop.pretendo.cc", q).body, &v); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, c := range v.Contents.Content {
			names = append(names, c.Title.Name)
		}
		return names
	}
	// "pokemon" (no accent) matches the archive by name and by publisher; the homebrew PKSM doesn't say it.
	if got := get(url.Values{"freeword": {"pokemon"}}); len(got) != 2 || got[0] != "Pokémon™ Picross" {
		t.Errorf("pokemon: %v", got)
	}
	if got := get(url.Values{"freeword": {"checkpoint"}}); len(got) != 1 || got[0] != "Checkpoint" {
		t.Errorf("checkpoint: %v", got)
	}
	if got := get(url.Values{"freeword": {"pokemon"}, "sort": {"new"}}); len(got) != 2 || got[0] != "Other Game" {
		t.Errorf("sort=new: %v", got)
	}
	if got := get(url.Values{"limit": {"1"}, "offset": {"1"}}); len(got) != 1 || v.Contents.Total != 4 {
		t.Errorf("paging: %v total %d", got, v.Contents.Total)
	}
	if seasonalTelop(time.Date(2026, 12, 5, 0, 0, 0, 0, time.UTC)) == "" || seasonalTelop(time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)) != "" {
		t.Error("seasonal telop")
	}
}
