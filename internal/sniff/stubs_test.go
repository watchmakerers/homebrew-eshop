package sniff

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The three requests a 3DS made on its first sniffing run (device ID replaced).
const titleHashReq = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:nus="urn:nus.wsapi.broadon.com">
<SOAP-ENV:Body>
<nus:GetSystemTitleHash><nus:Version>1.0</nus:Version><nus:MessageId>EC-1234-5678</nus:MessageId>
<nus:DeviceId>1234</nus:DeviceId><nus:RegionId>JPN</nus:RegionId><nus:CountryCode>JP</nus:CountryCode></nus:GetSystemTitleHash>
</SOAP-ENV:Body></SOAP-ENV:Envelope>`

func TestStubs(t *testing.T) {
	s := &Stubs{HashFile: filepath.Join(t.TempDir(), "titlehash")}
	req := func(method, target string, body string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		return r
	}

	rep := s.Respond("ninja.ctr.shop.pretendo.cc", req("GET", "/ninja/ws/service_hosts?country=JP&lang=ja&shop_id=1&_type=json", ""), nil)
	var hosts struct {
		Services struct {
			Service []struct{ Name, Origin_fqdn string }
		}
	}
	if rep == nil || json.Unmarshal(rep.body, &hosts) != nil || len(hosts.Services.Service) != 3 ||
		hosts.Services.Service[1].Origin_fqdn != "samurai.ctr.shop.pretendo.cc" {
		t.Fatalf("service_hosts: %+v", rep)
	}

	rep = s.Respond("ninja.ctr.shop.pretendo.cc", req("GET", "/ninja/ws/country/JP?lang=ja&shop_id=1&_type=json", ""), nil)
	if rep == nil || !strings.Contains(string(rep.body), `"iso_code":"JP"`) {
		t.Fatalf("country: %+v", rep)
	}
	// The eShop's country parser (0x326b4c in TIGER 8.17) reads price_format.formats.pattern_id as a string;
	// anywhere else, the parse fails and the shop errors 007-2001 after the ticket sync.
	var country struct {
		Detail struct {
			PriceFormat struct {
				Formats struct {
					PatternID *string `json:"pattern_id"`
				} `json:"formats"`
			} `json:"price_format"`
		} `json:"country_detail"`
	}
	if json.Unmarshal(rep.body, &country) != nil || country.Detail.PriceFormat.Formats.PatternID == nil {
		t.Fatalf("country: price_format.formats.pattern_id missing: %s", rep.body)
	}

	var resp struct {
		Body struct {
			R struct {
				XMLName   xml.Name
				DeviceId  string
				MessageId string
				ErrorCode string
				TitleHash string
			} `xml:",any"`
		}
	}
	ask := func() string {
		rep := s.Respond("nus.c.shop.pretendo.cc", req("POST", "/nus/services/NetUpdateSOAP", ""), []byte(titleHashReq))
		if rep == nil {
			t.Fatal("nus: no reply")
		}
		if err := xml.Unmarshal(rep.body, &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Body.R.TitleHash
	}
	h1 := ask()
	if resp.Body.R.XMLName.Local != "GetSystemTitleHashResponse" || resp.Body.R.XMLName.Space != "urn:nus.wsapi.broadon.com" ||
		resp.Body.R.DeviceId != "1234" || resp.Body.R.MessageId != "EC-1234-5678" || resp.Body.R.ErrorCode != "0" || len(h1) != 32 {
		t.Fatalf("title hash reply: %+v", resp.Body.R)
	}
	// Same hash after a restart.
	if h2 := (&Stubs{HashFile: s.HashFile}).titleHashOrFail(t); h2 != h1 {
		t.Fatalf("hash changed across restarts: %s -> %s", h1, h2)
	}

	// GetSystemUpdate must hand back exactly the installed titles and versions, with IDs in hex.
	update := strings.Replace(strings.ReplaceAll(titleHashReq, "GetSystemTitleHash", "GetSystemUpdate"), "</nus:CountryCode>",
		"</nus:CountryCode><nus:TitleVersion><nus:TitleId>1127205576916994</nus:TitleId><nus:Version>8192</nus:Version></nus:TitleVersion>"+
			"<nus:TitleVersion><nus:TitleId>1126106065310978</nus:TitleId><nus:Version>1031</nus:Version></nus:TitleVersion>", 1)
	rep = s.Respond("nus.c.shop.pretendo.cc", req("POST", "/nus/services/NetUpdateSOAP", ""), []byte(update))
	want := "<TitleVersion><TitleId>0004013000004002</TitleId><Version>8192</Version>"
	if rep == nil || !strings.Contains(string(rep.body), want) || strings.Count(string(rep.body), "<TitleVersion>") != 2 ||
		!strings.Contains(string(rep.body), "<TitleHash>"+h1) {
		t.Fatalf("update reply should echo the installed titles: %s", rep.body)
	}
	bad := strings.Replace(update, "<nus:Version>8192", "<nus:Version>x", 1)
	if s.Respond("nus.c.shop.pretendo.cc", req("POST", "/nus/services/NetUpdateSOAP", ""), []byte(bad)) != nil {
		t.Fatal("answered an update request it couldn't parse")
	}

	for _, what := range []string{"news", "directories", "telops", "languages"} {
		rep := s.Respond("samurai.ctr.shop.pretendo.cc", req("GET", "/samurai/ws/JP/"+what+"?lang=ja&shop_id=1&_type=json", ""), nil)
		if rep == nil || !json.Valid(rep.body) {
			t.Errorf("samurai %s: %+v", what, rep)
		}
	}
	if s.Respond("samurai.ctr.shop.pretendo.cc", req("GET", "/samurai/ws/JP/titles", ""), nil) != nil {
		t.Fatal("unknown request got a stub")
	}

	sess := s.Respond("ninja.ctr.shop.pretendo.cc", req("POST", "/ninja/ws/my/session/!open?_type=json", ""),
		[]byte("friend_code=0&country=JP&lang=ja&shop_id=1&device_token=x&device_account=987654&device_id=1234"))
	if sess == nil || !strings.HasPrefix(string(sess.body), `{"session_config":{"pid":987654,"account_id":"987654","country":"JP","saved_lang":"ja",`) ||
		!strings.HasSuffix(string(sess.body), `"auto_billing_contracted":false,"id":"1234"}}`) {
		t.Fatalf("session open (field order matters): %s", sess.body)
	}
	if c := sess.header.Get("Set-Cookie"); !strings.HasPrefix(c, "PHPSESSID=") {
		t.Fatalf("session open must set a session cookie, got %q", c)
	}
	for _, p := range []string{"balance/current", "wishlist", "wishlist/notice", "shared_title_ids", "owned_coupons", "tax_location", "language", "account/ctr/!migrate_without_nna"} {
		if rep := s.Respond("ninja.ctr.shop.pretendo.cc", req("GET", "/ninja/ws/my/"+p, ""), nil); rep == nil || !json.Valid(rep.body) {
			t.Errorf("ninja my/%s: %+v", p, rep)
		}
	}
	if rep := s.Respond("l-npns.app.pretendo.cc", req("POST", "/api/v1/platforms/3ds/devices.json", ""), nil); rep == nil ||
		rep.status != 201 || !json.Valid(rep.body) || !strings.HasPrefix(string(rep.body), `{"id":1,"device_id":"1","token":"`) {
		t.Errorf("npns register: %+v", rep)
	}
	if rep := s.Respond("ninja.ctr.shop.pretendo.cc", req("POST", "/ninja/ws/my/npns_status?shop_id=1&_type=json", ""), []byte("device_id=1&ready=true")); rep == nil {
		t.Error("npns_status: no reply")
	}
	if rep := s.Respond("samurai.ctr.shop.pretendo.cc", req("GET", "/samurai/ws/JP/directory/1?lang=ja", ""), nil); rep == nil || !json.Valid(rep.body) {
		t.Errorf("directory: %+v", rep)
	}

	acct := strings.NewReplacer("<nus:RegionId>JPN</nus:RegionId>", "<ecs:Region>JPN</ecs:Region><ecs:Country>JP</ecs:Country>",
		"xmlns:nus", "xmlns:ecs", "nus:", "ecs:", "urn:nus.", "urn:ecs.", "GetSystemTitleHash", "GetAccountStatus").Replace(titleHashReq)
	rep = s.Respond("ecs.c.shop.pretendo.cc", req("POST", "/ecs/services/ECommerceSOAP", ""), []byte(acct))
	if rep == nil {
		t.Fatal("ecs: no reply")
	}
	for _, want := range []string{`<GetAccountStatusResponse xmlns="urn:ecs.wsapi.broadon.com">`, "<AccountStatus>R</AccountStatus>",
		"<Currency>JPY</Currency>", "<URI>https://ecs.c.shop.pretendo.cc/ecs/services/ECommerceSOAP</URI>", "<MessageId>EC-1234-5678</MessageId>"} {
		if !strings.Contains(string(rep.body), want) {
			t.Errorf("ecs reply lacks %s:\n%s", want, rep.body)
		}
	}
	if err := xml.Unmarshal(rep.body, new(any)); err != nil {
		t.Errorf("ecs reply isn't XML: %v", err)
	}
}

func (s *Stubs) titleHashOrFail(t *testing.T) string {
	h, err := s.titleHash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}
