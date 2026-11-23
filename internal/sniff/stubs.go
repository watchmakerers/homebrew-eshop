package sniff

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Stubs answer the requests the eShop app makes before it shows anything, so each sniffing run gets one step
// further. Formats follow ReShop-3ds's 2022 servers (MIT, github.com/ReShop-3ds) and ihaveamac/nusserver.
// A canned file in -responses for the same path takes precedence over a stub.
type Stubs struct {
	// HashFile keeps the TitleHash we report, so it stays the same across runs (the console compares it).
	HashFile string
	// Shop, if set, serves categories, title lists and images from the real catalog instead of placeholders.
	Shop *Shop

	mu   sync.Mutex
	hash string
}

type stubReply struct {
	name        string
	contentType string
	body        []byte
	header      http.Header // extra response headers (may be nil)
	status      int         // 0 means 200
	// serve, if set, writes the body instead of body (for large files); headers above are already set.
	serve func(http.ResponseWriter, *http.Request)
}

// withSession adds what ReShop's PHP server sent with every reply (its db.php calls session_start()): a session
// cookie and PHP's no-cache headers. The eShop failed with 007-2001 right after a session/!open reply without them.
func withSession(rep *stubReply) *stubReply {
	id := make([]byte, 16)
	rand.Read(id)
	rep.header = http.Header{
		"Set-Cookie":    {"PHPSESSID=" + hex.EncodeToString(id) + "; path=/"},
		"Expires":       {"Thu, 19 Nov 1981 08:52:00 GMT"},
		"Cache-Control": {"no-store, no-cache, must-revalidate"},
		"Pragma":        {"no-cache"},
	}
	return rep
}

var countryPath = regexp.MustCompile(`^/ninja/ws/country/([A-Za-z]{2})$`)

// Respond returns a reply for a known request, or nil.
func (s *Stubs) Respond(host string, r *http.Request, body []byte) *stubReply {
	switch {
	case strings.HasPrefix(host, "ninja.") && r.URL.Path == "/ninja/ws/service_hosts":
		return s.serviceHosts(host)
	case strings.HasPrefix(host, "ninja.") && countryPath.MatchString(r.URL.Path):
		return s.country(strings.ToUpper(countryPath.FindStringSubmatch(r.URL.Path)[1]))
	case strings.HasPrefix(host, "ninja.") && s.Shop != nil && ninjaECInfoPath.MatchString(r.URL.Path):
		n, _ := strconv.Atoi(ninjaECInfoPath.FindStringSubmatch(r.URL.Path)[2])
		return s.Shop.ecInfo(n)
	case strings.HasPrefix(host, "ninja.") && s.Shop != nil && ninjaPricesPath.MatchString(r.URL.Path):
		return s.Shop.onlinePrices(ninjaPricesPath.FindStringSubmatch(r.URL.Path)[1], r.URL.Query())
	case strings.HasPrefix(host, "ninja.") && s.Shop != nil && ninjaPrePurchase.MatchString(r.URL.Path):
		m := ninjaPrePurchase.FindStringSubmatch(r.URL.Path)
		n, _ := strconv.Atoi(m[2])
		return s.Shop.prepurchaseInfo(m[1], n)
	case strings.HasPrefix(host, "ninja.") && strings.HasPrefix(r.URL.Path, "/ninja/ws/my/"):
		return s.ninjaMy(strings.TrimPrefix(r.URL.Path, "/ninja/ws/my/"), body)
	case strings.HasPrefix(host, "nus.") && r.URL.Path == "/nus/services/NetUpdateSOAP":
		return s.nus(host, body)
	case strings.HasPrefix(host, "ecs.") && r.URL.Path == "/ecs/services/ECommerceSOAP":
		return s.ecs(host, body)
	case strings.HasPrefix(host, "cas.") && r.URL.Path == "/cas/services/CatalogingSOAP" && s.Shop != nil:
		return s.cas(body)
	case strings.HasPrefix(host, "l-npns.") && r.URL.Path == "/api/v1/platforms/3ds/devices.json":
		return npnsRegister()
	case strings.HasPrefix(host, "ccs.") && s.Shop != nil:
		return s.Shop.cdn(r.URL.Path)
	case strings.HasPrefix(host, "img.") && s.Shop != nil:
		return s.Shop.image(r.URL.Path)
	case strings.HasPrefix(host, "samurai."):
		if m := samuraiPath.FindStringSubmatch(r.URL.Path); m != nil {
			if m[2] == "directories" && s.Shop != nil {
				return s.Shop.directories(host)
			}
			if m[2] == "telops" && s.Shop != nil {
				return jsonReply("samurai telops (shop)", map[string]any{"telops": map[string]any{"telop": s.Shop.Telops()}, "length": len(s.Shop.Telops())})
			}
			return s.samurai(m[2], r.URL.Query().Get("lang"))
		}
		if m := samuraiTitlePath.FindStringSubmatch(r.URL.Path); m != nil && s.Shop != nil {
			n, _ := strconv.Atoi(m[2])
			return s.Shop.title(host, n)
		}
		if m := samuraiDirPath.FindStringSubmatch(r.URL.Path); m != nil {
			if s.Shop != nil {
				n, _ := strconv.Atoi(m[2])
				return s.Shop.directory(host, n, r.URL.Query())
			}
			return s.directory(m[2])
		}
		if strings.HasSuffix(r.URL.Path, "/eshop_message/about") { // shown when the shop account is new
			return jsonReply("samurai about", map[string]any{"text": map[string]any{"type": "html",
				"body": "Homebrew eShop\n\nThis shop lists free homebrew software from community sources. Nothing here is sold by or affiliated with Nintendo."}})
		}
	}
	return nil
}

// npnsRegister answers the console registering with the push notification server. Nobody has documented this
// reply; this one (status 201, every usual name for an ID and token) is the one the eShop accepted, after it
// rejected {} with status 200. The body is written out by hand to keep the exact field order that worked.
func npnsRegister() *stubReply {
	b := make([]byte, 20)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	body := fmt.Sprintf(`{"id":1,"device_id":"1","token":"%[1]s","device_token":"%[1]s","status":"registered",`+
		`"device":{"id":1,"device_id":"1","token":"%[1]s","device_token":"%[1]s"}}`, tok)
	return &stubReply{name: "npns register", contentType: "application/json", body: []byte(body), status: http.StatusCreated}
}

// /samurai/ws/<country>/<what>
var samuraiPath = regexp.MustCompile(`^/samurai/ws/([A-Za-z]{2})/([a-z_]+)$`)

// /samurai/ws/<country>/directory/<id>: one category's contents
var samuraiDirPath = regexp.MustCompile(`^/samurai/ws/([A-Za-z]{2})/directory/([0-9]+)$`)

// directory lists a category's titles. Empty for now; eshopd fills it from the catalog later.
func (s *Stubs) directory(id string) *stubReply {
	n, _ := strconv.Atoi(id)
	return jsonReply("samurai directory "+id, map[string]any{"directory": map[string]any{
		"id": n, "name": "Homebrew", "icon_url": "", "icon_width": 76, "icon_height": 58, "banner_url": "",
		"contents": map[string]any{"content": []any{}, "length": 0, "offset": 0, "total": 0},
	}})
}

// ninjaMy answers the per-account requests (/ninja/ws/my/...). Every account is empty: no balance, nothing
// owned, nothing wished for, no coupons, parental controls off.
func (s *Stubs) ninjaMy(what string, body []byte) *stubReply {
	switch what {
	case "session/!open":
		form, _ := url.ParseQuery(string(body))
		account := form.Get("device_account")
		pid, err := strconv.ParseUint(account, 10, 64)
		if err != nil {
			account, pid = "1", 1
		}
		lang := form.Get("lang")
		if lang == "" {
			lang = "en"
		}
		now := time.Now().UnixMilli()
		// A struct, not a map, so the fields go out in this order: the order ReShop's working reply (and
		// Nintendo's) used. The eShop rejected the same fields in alphabetical order with 007-2001.
		type device struct {
			Name                   string `json:"name"`
			InitialDeviceAccountID string `json:"initial_device_account_id"`
			NPNSReady              bool   `json:"npns_ready"`
			ID                     int    `json:"id"`
		}
		type parental struct {
			Device string `json:"device"`
			Type   string `json:"type"`
			Value  int    `json:"value"`
		}
		type sessionConfig struct {
			PID                      uint64 `json:"pid"`
			AccountID                string `json:"account_id"`
			Country                  string `json:"country"`
			SavedLang                string `json:"saved_lang"`
			ShopAccountInitialized   bool   `json:"shop_account_initialized"`
			DeviceLinkUpdated        bool   `json:"device_link_updated"`
			OwnedTitlesModified      int64  `json:"owned_titles_modified"`
			SharedTitlesLastModified int64  `json:"shared_titles_last_modified"`
			Age                      int    `json:"age"`
			ServerTime               int64  `json:"server_time"`
			Devices                  struct {
				Device []device `json:"device"`
			} `json:"devices"`
			ParentalControls struct {
				ParentalControl []parental `json:"parental_control"`
			} `json:"parental_controls"`
			AutoBillingContracted bool   `json:"auto_billing_contracted"`
			ID                    string `json:"id"`
		}
		c := sessionConfig{
			PID: pid, AccountID: account, Country: form.Get("country"), SavedLang: lang,
			// Already set up: with false (what ReShop sent) the eShop ran first-time setup, which registers the
			// console with the push notification server, whose reply format nobody has documented.
			ShopAccountInitialized: true,
			OwnedTitlesModified:    now, SharedTitlesLastModified: now, Age: 21, ServerTime: now, ID: form.Get("device_id"),
		}
		// npns_ready=true tells the eShop push is already set up, so it doesn't loop register -> npns_status ->
		// reopen waiting for this to flip (that loop, 8x with a 14s push-connection timeout each, ended in 007-2001).
		c.Devices.Device = []device{{Name: "CTR", InitialDeviceAccountID: account, NPNSReady: true, ID: 4}}
		for _, kind := range []string{"game_rating_age", "game_rating_lock", "shopping"} {
			c.ParentalControls.ParentalControl = append(c.ParentalControls.ParentalControl, parental{"CTR", kind, 0})
		}
		return withSession(jsonReply("ninja session open", map[string]any{"session_config": c}))
	case "npns_status": // the console reporting it's ready for push notifications (form: device_id, ready)
		return &stubReply{name: "ninja npns status", contentType: "application/json;charset=UTF-8"}
	case "session/!close":
		return &stubReply{name: "ninja session close", contentType: "application/json;charset=UTF-8"}
	case "account/ctr/!migrate_without_nna":
		return jsonReply("ninja migrate", map[string]any{})
	case "language":
		return jsonReply("ninja my language", map[string]any{"session_config": map[string]any{"saved_lang": "en"}})
	case "balance/current":
		return jsonReply("ninja balance", map[string]any{"balance": map[string]any{"amount": "0", "currency": "FREE", "raw_value": "0"}})
	case "wishlist":
		return jsonReply("ninja wishlist", map[string]any{"wishlist": map[string]any{"total": 0}})
	case "wishlist/notice":
		return jsonReply("ninja wishlist notice", map[string]any{"wishlist_notice": map[string]any{"wished_title_id": []any{}, "total": 0}})
	case "shared_title_ids":
		return jsonReply("ninja owned titles", map[string]any{"owned_titles": map[string]any{"owned_title": []any{}}})
	case "owned_coupons":
		return jsonReply("ninja coupons", map[string]any{"coupons": map[string]any{}})
	case "tax_location":
		// Asked for when a download starts; a 404 here is 007-2404. The eShop's parser (TIGER 0x344408) only
		// reads the body on US (country 49) and Canadian (18) consoles: tax_location {postal_code, city, county,
		// state, id} for the US, {state, id, state_code} for Canada (sub-parser 0x3459d8). Every other country
		// ignores it, so the fields here only matter there, and are placeholders.
		return jsonReply("ninja tax location", map[string]any{"tax_location": map[string]any{
			"id": 1, "postal_code": "", "city": "", "county": "", "state": "", "state_code": "",
		}})
	}
	return nil
}

// samurai is the catalog server. These are placeholders so the shop opens; the real catalog comes from eshopd.
func (s *Stubs) samurai(what, lang string) *stubReply {
	if lang == "" {
		lang = "en"
	}
	switch what {
	case "news":
		return jsonReply("samurai news", map[string]any{"news": map[string]any{
			"news_entry": []map[string]any{{
				"id":          1,
				"headline":    "Homebrew eShop",
				"description": "This shop is served by homebrew-eshop. Nothing here is for sale.",
				"date":        time.Now().Unix(),
			}},
			"length": 1,
		}})
	case "telops": // the scrolling ticker
		return jsonReply("samurai telops", map[string]any{"telops": map[string]any{"telop": []string{"Welcome to the homebrew eShop."}}, "length": 1})
	case "languages":
		return jsonReply("samurai languages", map[string]any{"languages": map[string]any{"language": []map[string]string{{"iso_code": lang, "name": lang}}}})
	case "directories": // the category list
		return jsonReply("samurai directories", map[string]any{"directories": map[string]any{
			"directory": []map[string]any{{
				"id": 1, "index": 1, "name": "Homebrew", "type": "normal", "standard": true, "new": false,
				"icon_url": "", "icon_width": 128, "icon_height": 96, "banner_url": "",
			}},
			"length":     1,
			"catalog_id": 1,
		}})
	}
	return nil
}

func jsonReply(name string, v any) *stubReply {
	data, _ := json.Marshal(v)
	return &stubReply{name: name, contentType: "application/json;charset=UTF-8", body: data}
}

// serviceHosts tells the app where the other eShop servers are. They're named under the same domain the app
// used for ninja (e.g. ninja.ctr.shop.pretendo.cc -> samurai.ctr.shop.pretendo.cc), which our DNS also intercepts.
func (s *Stubs) serviceHosts(ninjaHost string) *stubReply {
	base := strings.TrimPrefix(ninjaHost, "ninja.ctr.shop.")
	if base == ninjaHost {
		base = strings.TrimPrefix(ninjaHost, "ninja.")
	}
	type svc struct {
		Name   string `json:"name"`
		Origin string `json:"origin_fqdn"`
		CDN    string `json:"cdn_fqdn,omitempty"`
	}
	samurai := "samurai.ctr.shop." + base
	return jsonReply("ninja service_hosts", map[string]any{"services": map[string]any{"service": []svc{
		{Name: "EOU", Origin: "eou.c.shop." + base, CDN: "eou.c.shop." + base},
		{Name: "SAMURAI_CTR", Origin: samurai, CDN: samurai},
		{Name: "CCIF", Origin: "ccif.ctr.shop." + base},
	}}})
}

// country describes the shop for a region. Nothing is for sale, so payment options are all off.
func (s *Stubs) country(code string) *stubReply {
	return jsonReply("ninja country", map[string]any{"country_detail": map[string]any{
		"region_code":                     code,
		"iso_code":                        code,
		"name":                            code,
		"eshop_available":                 true,
		"default_language_code":           "en",
		"language_selectable":             false,
		"default_timezone":                "+00:00",
		"max_cash":                        map[string]any{"amount": "0", "currency": "FREE", "raw_value": "0"},
		"loyalty_system_available":        false,
		"legal_payment_message_required":  false,
		"legal_business_message_required": false,
		"tax_excluded_country":            false,
		"tax_free_country":                true,
		"prepaid_card_available":          false,
		"credit_card_available":           false,
		"credit_card_store_available":     false,
		"jcb_security_code_available":     false,
		"nfc_available":                   false,
		"coupon_available":                false,
		"my_coupon_available":             false,
		"price_format": map[string]any{
			"positive_prefix": "", "positive_suffix": "", "negative_prefix": "-", "negative_suffix": "",
			// The eShop reads price_format.formats.pattern_id (a string). With pattern_id beside "formats"
			// instead of inside it, the country parse fails and the eShop later shows that as 007-2001.
			"formats": map[string]any{"format": []map[string]string{{"value": "#", "digit": "#"}}, "pattern_id": "1"},
		},
	}})
}

type soapAction struct {
	XMLName   xml.Name
	Version   string `xml:"Version"`
	DeviceID  string `xml:"DeviceId"`
	MessageID string `xml:"MessageId"`
	AccountID string `xml:"AccountId"`
	Region    string `xml:"Region"`
	Country   string `xml:"Country"`
	// CAS ListTitlesEx, ECS AccountPurchaseTitle: the titles asked about, 16 hex digits.
	TitleIDs []string `xml:"TitleId"`
	// ECS AccountGetETickets: decimal ticket IDs.
	TicketIDs []string `xml:"TicketId"`
	// GetSystemUpdate: the system titles installed on the console. TitleId is decimal here.
	TitleVersions []struct {
		TitleID string `xml:"TitleId"`
		Version string `xml:"Version"`
	} `xml:"TitleVersion"`
}

type soapRequest struct {
	Body struct {
		Action soapAction `xml:",any"`
	} `xml:"Body"`
}

func parseSOAP(body []byte, defaultNS string) (soapAction, bool) {
	var req soapRequest
	if err := xml.Unmarshal(body, &req); err != nil || req.Body.Action.XMLName.Local == "" {
		return soapAction{}, false
	}
	if req.Body.Action.XMLName.Space == "" {
		req.Body.Action.XMLName.Space = defaultNS
	}
	return req.Body.Action, true
}

// soapReply wraps fields in the <ActionResponse> envelope every BroadOn SOAP service uses, echoing the request's
// Version, DeviceId and MessageId.
func soapReply(a soapAction, extra string) *stubReply {
	action := a.XMLName.Local
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` +
		`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
		`<soapenv:Body>`)
	fmt.Fprintf(&b, `<%sResponse xmlns="%s">`, action, escape(a.XMLName.Space))
	b.WriteString(el("Version", a.Version) + el("DeviceId", a.DeviceID) + el("MessageId", a.MessageID) +
		el("TimeStamp", fmt.Sprint(time.Now().UnixMilli())) + el("ErrorCode", "0") + extra)
	fmt.Fprintf(&b, `</%sResponse></soapenv:Body></soapenv:Envelope>`, action)
	service := strings.TrimPrefix(strings.SplitN(a.XMLName.Space, ".", 2)[0], "urn:") // urn:ecs.wsapi.broadon.com -> ecs
	return &stubReply{name: service + " " + action, contentType: "text/xml;charset=utf-8", body: b.Bytes()}
}

var currencies = map[string]string{"JPN": "JPY", "USA": "USD", "EUR": "EUR", "AUS": "AUD", "KOR": "KRW", "TWN": "TWD", "CHN": "CNY"}

// ecs is the account service. Every console gets a registered account with no balance and no purchases, and
// service URLs that point back at us.
func (s *Stubs) ecs(host string, body []byte) *stubReply {
	a, ok := parseSOAP(body, "urn:ecs.wsapi.broadon.com")
	if !ok {
		return nil
	}
	base := strings.TrimPrefix(host, "ecs.c.shop.")
	switch a.XMLName.Local {
	case "GetAccountStatus":
		account := a.AccountID
		if account == "" {
			h := fnv.New32a()
			h.Write([]byte(a.DeviceID))
			account = fmt.Sprint(h.Sum32() & 0x7FFFFFFF)
		}
		currency := currencies[strings.ToUpper(a.Region)]
		if currency == "" {
			currency = "USD"
		}
		url := func(name, u string) string {
			return "<ServiceURLs>" + el("Name", name) + el("URI", u) + "</ServiceURLs>"
		}
		return soapReply(a, el("ServiceStandbyMode", "false")+el("AccountId", account)+el("AccountStatus", "R")+
			"<Balance>"+el("Amount", "0")+el("Currency", currency)+"</Balance>"+
			el("EulaVersion", "0")+el("Country", a.Country)+el("Region", a.Region)+
			url("ContentPrefixURL", "http://ccs.cdn.c.shop."+base+"/ccs/download")+
			url("UncachedContentPrefixURL", "https://ccs.c.shop."+base+"/ccs/download")+
			url("SystemContentPrefixURL", "http://nus.cdn.c.shop."+base+"/ccs/download")+
			url("SystemUncachedContentPrefixURL", "https://ccs.c.shop."+base+"/ccs/download")+
			url("EcsURL", "https://ecs.c.shop."+base+"/ecs/services/ECommerceSOAP")+
			url("IasURL", "https://ias.c.shop."+base+"/ias/services/IdentityAuthenticationSOAP")+
			url("CasURL", "https://cas.c.shop."+base+"/cas/services/CatalogingSOAP")+
			url("NusURL", "https://nus.c.shop."+base+"/nus/services/NetUpdateSOAP")+
			el("IVSSyncFlag", "false")+el("CountryAttribits", "15")) // sic: the real service spells it this way
	case "AccountPurchaseTitle":
		if s.Shop != nil {
			return s.Shop.purchaseTitle(a)
		}
	case "AccountGetETickets":
		if s.Shop != nil {
			return s.Shop.getETickets(a)
		}
	case "AccountListETicketIds":
		// A homebrew account owns nothing, so this must return an empty ticket list. NIM (not the eShop app)
		// parses it: our empty reply currently makes NIM error 007-2001, and a *non-empty* list only moves the
		// error to AccountGetETickets (NIM then demands the real signed ticket for each id). The right fix is
		// the exact empty-list reply NIM accepts, which needs tracing NIM (0004013000002C02); kept empty here.
		return soapReply(a, el("ServiceStandbyMode", "false"))
	}
	return nil
}

// nus answers the system update check. GetSystemUpdate gets an empty title list: "nothing to update". We never
// offer an update, so a console can't be talked into installing anything from here.
func (s *Stubs) nus(host string, body []byte) *stubReply {
	a, ok := parseSOAP(body, "urn:nus.wsapi.broadon.com")
	if !ok {
		return nil
	}
	hash, err := s.titleHash()
	if err != nil {
		return nil
	}

	switch a.XMLName.Local {
	case "GetSystemTitleHash":
		return soapReply(a, el("TitleHash", hash))
	case "GetSystemUpdate":
		// The "latest" system version is exactly what the console already has: every title it reported, at the
		// version it reported. Nothing is newer, so nothing gets downloaded.
		var list strings.Builder
		for _, tv := range a.TitleVersions {
			id, err1 := strconv.ParseUint(tv.TitleID, 10, 64)
			ver, err2 := strconv.ParseUint(tv.Version, 10, 16)
			if err1 != nil || err2 != nil {
				return nil // unexpected format: don't guess, leave it unanswered and logged
			}
			list.WriteString("<TitleVersion>" + el("TitleId", fmt.Sprintf("%016X", id)) + el("Version", fmt.Sprint(ver)) +
				el("FsSize", "0") + el("TicketSize", "848") + el("TMDSize", "0") + "</TitleVersion>")
		}
		prefix := "http://" + strings.Replace(host, "nus.", "nus.cdn.", 1) + "/ccs/download"
		return soapReply(a, el("ContentPrefixURL", prefix)+el("UncachedContentPrefixURL", "https://"+strings.Replace(host, "nus.", "ccs.", 1)+"/ccs/download")+
			list.String()+el("UploadAuditData", "1")+el("TitleHash", hash))
	}
	return nil // GetSystemCommonETicket etc.: leave unanswered and logged until we know we need them
}

func (s *Stubs) titleHash() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hash != "" {
		return s.hash, nil
	}
	if data, err := os.ReadFile(s.HashFile); err == nil && len(bytes.TrimSpace(data)) == 32 {
		s.hash = string(bytes.TrimSpace(data))
		return s.hash, nil
	}
	buf := make([]byte, 16)
	rand.Read(buf)
	s.hash = strings.ToUpper(hex.EncodeToString(buf))
	if err := os.MkdirAll(filepath.Dir(s.HashFile), 0o700); err != nil {
		return "", err
	}
	return s.hash, os.WriteFile(s.HashFile, []byte(s.hash+"\n"), 0o600)
}

func el(name, value string) string { return "<" + name + ">" + escape(value) + "</" + name + ">" }

func escape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
