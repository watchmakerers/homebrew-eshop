package sniff

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"homebrew-eshop/internal/catalog"
)

func TestTitlePages(t *testing.T) {
	titles := []catalog.Title{
		{Name: "Known ID", TitleID: 0x000400000F800100, Size: "26 MiB", CIA: &catalog.CIASource{URL: "x"}},
		{Name: "No ID", Description: "d", CIA: &catalog.CIASource{URL: "y"}},
	}
	s := &Stubs{Shop: &Shop{Titles: func() []catalog.Title { return titles }}}
	known, noID := ShopID(titles[0]), ShopID(titles[1])
	req := func(method, target, _ string) *http.Request { return httptest.NewRequest(method, target, nil) }

	var ec struct {
		Info struct {
			TitleID string `json:"title_id"`
			Version *int   `json:"title_version"`
			Size    int64  `json:"content_size"`
		} `json:"title_ec_info"`
	}
	rep := s.Respond("ninja.ctr.shop.pretendo.cc", req("GET", fmt.Sprintf("/ninja/ws/JP/title/%d/ec_info?shop_id=1&lang=ja&_type=json", known), ""), nil)
	if rep == nil || json.Unmarshal(rep.body, &ec) != nil || ec.Info.TitleID != "000400000F800100" || ec.Info.Version == nil ||
		ec.Info.Size != 26<<20 {
		t.Fatalf("ec_info: %+v", rep)
	}
	rep = s.Respond("ninja.ctr.shop.pretendo.cc", req("GET", fmt.Sprintf("/ninja/ws/JP/title/%d/ec_info", noID), ""), nil)
	if rep == nil || json.Unmarshal(rep.body, &ec) != nil || len(ec.Info.TitleID) != 16 || ec.Info.TitleID[:8] != "00040000" {
		t.Fatalf("ec_info placeholder id: %+v", rep)
	}
	if rep := s.Respond("ninja.ctr.shop.pretendo.cc", req("GET", "/ninja/ws/JP/title/12345/ec_info", ""), nil); rep != nil {
		t.Fatalf("unknown title should 404: %s", rep.body)
	}

	var page struct {
		Title struct {
			ID          int    `json:"id"`
			Name        string `json:"name"`
			FormalName  string `json:"formal_name"`
			Description string `json:"description"`
			EshopSales  bool   `json:"eshop_sales"`
		} `json:"title"`
	}
	rep = s.Respond("samurai.ctr.shop.pretendo.cc", req("GET", fmt.Sprintf("/samurai/ws/JP/title/%d?lang=ja&shop_id=1&_type=json", noID), ""), nil)
	if rep == nil || json.Unmarshal(rep.body, &page) != nil || page.Title.ID != noID || page.Title.FormalName != "No ID" ||
		!page.Title.EshopSales || page.Title.Description == "" {
		t.Fatalf("title: %+v", rep)
	}

	var prices struct {
		OnlinePrices struct {
			OnlinePrice []struct {
				TitleID int64  `json:"title_id"`
				Status  string `json:"eshop_sales_status"`
				Price   struct {
					Regular struct {
						Currency string `json:"currency"`
						Raw      string `json:"raw_value"`
					} `json:"regular_price"`
				} `json:"price"`
			} `json:"online_price"`
		} `json:"online_prices"`
	}
	rep = s.Respond("ninja.ctr.shop.pretendo.cc", req("GET", fmt.Sprintf("/ninja/ws/JP/titles/online_prices?title%%5B%%5D=%014d,%014d&lang=ja&include_coupon=true&shop_id=1&_type=json", known, noID), ""), nil)
	if rep == nil || json.Unmarshal(rep.body, &prices) != nil || len(prices.OnlinePrices.OnlinePrice) != 2 {
		t.Fatalf("online_prices: %+v", rep)
	}
	p := prices.OnlinePrices.OnlinePrice[0]
	if p.TitleID != int64(known) || p.Status != "onsale" || p.Price.Regular.Currency != "JPY" || p.Price.Regular.Raw != "0" {
		t.Fatalf("online_prices entry: %s", rep.body)
	}
}
