package sniff

import (
	"bytes"
	"encoding/xml"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"homebrew-eshop/internal/catalog"
)

// The console's own ListTitlesEx request (device IDs blanked), answered for a title in the catalog.
func TestCASListTitlesEx(t *testing.T) {
	body, err := os.ReadFile("testdata/cas_listtitlesex.xml")
	if err != nil {
		t.Fatal(err)
	}
	titles := []catalog.Title{{Name: "Game", TitleID: 0x000400000FEF0300, CIA: &catalog.CIASource{URL: "x"}}}
	st := &Stubs{Shop: &Shop{Titles: func() []catalog.Title { return titles }}}
	req := httptest.NewRequest("POST", "https://cas.c.shop.pretendo.cc/cas/services/CatalogingSOAP", bytes.NewReader(body))
	r := st.Respond("cas.c.shop.pretendo.cc", req, body)
	if r == nil {
		t.Fatal("no reply")
	}
	var env struct {
		Body struct {
			Resp struct {
				XMLName xml.Name
				Error   string `xml:"ErrorCode"`
				Total   int    `xml:"ListResultTotalSize"`
				Titles  []struct {
					TitleID string `xml:"TitleId"`
					Prices  struct {
						ItemID string `xml:"ItemId"`
						Amount string `xml:"Price>Amount"`
						Curr   string `xml:"Price>Currency"`
						Limit  string `xml:"Limits>Limits"`
						Kind   string `xml:"Limits>LimitKind"`
						Lic    string `xml:"LicenseKind"`
					} `xml:"Prices"`
				} `xml:"Titles"`
			} `xml:",any"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(r.body, &env); err != nil {
		t.Fatalf("%v\n%s", err, r.body)
	}
	resp := env.Body.Resp
	if resp.XMLName.Local != "ListTitlesExResponse" || resp.XMLName.Space != "urn:cas.wsapi.broadon.com" || resp.Error != "0" || resp.Total != 1 || len(resp.Titles) != 1 {
		t.Fatalf("reply: %s", r.body)
	}
	p := resp.Titles[0]
	if p.TitleID != "000400000FEF0300" || p.Prices.Amount != "0" || p.Prices.Curr != "JPY" || p.Prices.Kind != "PR" || p.Prices.Lic != "PERMANENT" || p.Prices.ItemID == "" {
		t.Errorf("title: %+v", p)
	}

	// A title we don't have gets no entry.
	other := strings.Replace(string(body), "000400000FEF0300", "0004000000123400", 1)
	r = st.Respond("cas.c.shop.pretendo.cc", req, []byte(other))
	if r == nil || bytes.Contains(r.body, []byte("<Titles>")) {
		t.Errorf("unknown title should get an empty list: %v", r)
	}
}
