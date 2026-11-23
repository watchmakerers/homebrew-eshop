package sniff

import (
	"fmt"
	"hash/fnv"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"homebrew-eshop/internal/catalog"
)

// Title pages. Formats come from the eShop app itself (TIGER 8.17): the title and online_prices layouts follow
// sample replies embedded in the binary, and ec_info follows its parser's key table (title_ec_info: title_id as a
// hex string, title_version and content_size as numbers, content_lock optional).

var (
	samuraiTitlePath = regexp.MustCompile(`^/samurai/ws/([A-Za-z]{2})/title/([0-9]+)$`)
	ninjaECInfoPath  = regexp.MustCompile(`^/ninja/ws/([A-Za-z]{2})/title/([0-9]+)/ec_info$`)
	ninjaPricesPath  = regexp.MustCompile(`^/ninja/ws/([A-Za-z]{2})/titles/online_prices$`)
	ninjaPrePurchase = regexp.MustCompile(`^/ninja/ws/([A-Za-z]{2})/title/([0-9]+)/prepurchase_info$`)
	sizeRe           = regexp.MustCompile(`^\s*([0-9.]+)\s*([KMG]i?B|B)?`)
)

// countryCurrencies maps the shop's two-letter country to its currency (currencies is keyed by region).
var countryCurrencies = map[string]string{"JP": "JPY", "US": "USD", "CA": "CAD", "GB": "GBP", "AU": "AUD", "KR": "KRW", "TW": "TWD", "HK": "HKD", "CN": "CNY",
	"DE": "EUR", "FR": "EUR", "IT": "EUR", "ES": "EUR", "NL": "EUR"}

// find returns the installable title with this shop ID.
func (s *Shop) find(id int) *catalog.Title {
	for _, t := range s.Titles() {
		if t.CIA != nil && ShopID(t) == id {
			t := t
			return &t
		}
	}
	return nil
}

// titleID is the 3DS title ID the console will install. Catalog entries without one (their CIA hasn't been read
// yet) get a stable placeholder in the homebrew range, derived from the shop ID.
func titleID(t *catalog.Title) uint64 {
	if t.TitleID != 0 {
		return t.TitleID
	}
	h := fnv.New32a()
	h.Write([]byte(t.Key()))
	return catalog.HomebrewTitleID(h.Sum32()&0xFFFFF | 0xF0000)
}

// contentSize parses the catalog's human size ("26 MiB") into bytes; 0 when unknown.
func contentSize(s string) int64 {
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	mult := map[string]float64{"": 1, "B": 1, "KB": 1e3, "KiB": 1 << 10, "MB": 1e6, "MiB": 1 << 20, "GB": 1e9, "GiB": 1 << 30}[m[2]]
	return int64(f * mult)
}

func genreOf(t *catalog.Title) string {
	if t.Backup {
		return "My Backups"
	}
	if len(t.Categories) > 0 {
		if n := categoryNames[strings.ToLower(t.Categories[0])]; n != "" {
			return n
		}
	}
	return "Homebrew"
}

// title is samurai's title detail page.
func (s *Shop) title(samuraiHost string, id int) *stubReply {
	if at := s.archiveTitle(int64(id)); at != nil {
		return s.archiveTitlePage(samuraiHost, at)
	}
	t := s.find(id)
	if t == nil {
		return nil
	}
	author := t.Author
	if author == "" {
		author = "Unknown"
	}
	desc := t.Description
	if a := s.backupArchive(t); a != nil && a.Description != "" {
		desc = a.Description
	}
	if t.Version != "" {
		desc += "\n\nVersion: " + t.Version
	}
	if t.License != "" {
		desc += "\nLicense: " + t.License
	}
	desc += "\nSource: " + t.Source
	disclaimer := "Homebrew software from the community. Not made or checked by Nintendo."
	if t.Backup {
		disclaimer = "Your own backup, served from your PC."
	}
	base := imgBase(samuraiHost)
	tid := titleID(t)
	if info, err := s.prepareFor(t, pageWait); err == nil { // same ID ec_info reports
		tid = info.titleID
	}
	return jsonReply(fmt.Sprintf("samurai title %d (%s)", id, t.Name), map[string]any{"title": map[string]any{
		"id":                    id,
		"name":                  t.Name,
		"formal_name":           t.Name,
		"title_id":              fmt.Sprintf("%016X", tid),
		"title_version":         0,
		"product_code":          fmt.Sprintf("HBR-N-%06X", id&0xFFFFFF),
		"description":           desc,
		"disclaimer":            disclaimer,
		"display_genre":         genreOf(t),
		"number_of_players":     "1",
		"publisher":             map[string]any{"id": 1, "name": author},
		"genres":                map[string]any{"genre": []map[string]any{{"id": 1, "name": genreOf(t)}}, "length": 1},
		"languages":             map[string]any{"language": []map[string]any{{"iso_code": "en", "name": "English"}}},
		"release_date_on_eshop": releaseDate(t.Updated),
		"icon_url":              fmt.Sprintf("%s/icon/%d.jpg", base, id),
		"banner_url":            fmt.Sprintf("%s/banner/%d.jpg", base, id),
		"ticket_available":      false,
		"retail_sales":          false,
		"eshop_sales":           true,
		"downloadable":          true,
		"movie_available":       false,
		"demo_available":        false,
		"aoc_available":         false,
		"in_app_purchase":       false,
		"new":                   isNew(t),
	}})
}

// ecInfo tells the eShop what it would download: title ID, version and size.
func (s *Shop) ecInfo(id int) *stubReply {
	t := s.find(id)
	if t == nil {
		return nil
	}
	tid, version, size, note := titleID(t), 0, contentSize(t.Size), ""
	if info, err := s.prepareFor(t, pageWait); err == nil { // exact numbers from the CIA itself
		tid, version, size = info.titleID, int(info.version), info.size
	} else {
		note = " [CIA not ready: " + err.Error() + "]"
	}
	return jsonReply(fmt.Sprintf("ninja ec_info %d (%s)%s", id, t.Name, note), map[string]any{"title_ec_info": map[string]any{
		"title_id":      fmt.Sprintf("%016X", tid),
		"title_version": version,
		"content_size":  size,
	}})
}

// onlinePrices prices every requested title: all free. The ids come as one comma-separated title[] value.
func (s *Shop) onlinePrices(country string, q url.Values) *stubReply {
	currency := countryCurrencies[strings.ToUpper(country)]
	if currency == "" {
		currency = "USD"
	}
	var list []map[string]any
	for _, v := range q["title[]"] {
		for _, f := range strings.Split(v, ",") {
			id, err := strconv.ParseInt(strings.TrimSpace(f), 10, 64)
			if err != nil {
				continue
			}
			if s.archiveTitle(id) != nil { // the old catalog: no longer sold
				list = append(list, map[string]any{"title_id": id, "eshop_sales_status": "sales_termination"})
				continue
			}
			list = append(list, map[string]any{
				"title_id":           id,
				"eshop_sales_status": "onsale",
				"price": map[string]any{"regular_price": map[string]any{
					"amount": "Free", "currency": currency, "raw_value": "0", "id": 1,
				}},
			})
		}
	}
	if list == nil {
		list = []map[string]any{}
	}
	return jsonReply(fmt.Sprintf("ninja online_prices (%d)", len(list)), map[string]any{"online_prices": map[string]any{"online_price": list}})
}

// prepurchaseInfo is the eShop app's check before "buying" (downloading) a title: what it costs and the balance
// before and after. UNVERIFIED: no reply body has been published and the app's parser hasn't been traced; this
// layout follows the order of the app's JSON key-path table (TIGER 0x3b3984: prepurchase_info -> purchasing_content,
// tax_excluded, current_balance.raw_value; payment_amount -> price.regular_price{amount,currency,raw_value,id},
// total_amount.raw_value, tax_amount.raw_value; pre_order). Everything is free.
func (s *Shop) prepurchaseInfo(country string, id int) *stubReply {
	t := s.find(id)
	if t == nil {
		return nil
	}
	currency := countryCurrencies[strings.ToUpper(country)]
	if currency == "" {
		currency = "USD"
	}
	money := func(amount string) map[string]any {
		return map[string]any{"amount": amount, "currency": currency, "raw_value": "0"}
	}
	regular := money("Free")
	regular["id"] = 1
	return jsonReply(fmt.Sprintf("ninja prepurchase_info %d (%s) [guessed layout]", id, t.Name), map[string]any{"prepurchase_info": map[string]any{
		"purchasing_content": map[string]any{"type": "title", "title": map[string]any{"id": id, "name": t.Name}},
		"tax_excluded":       false,
		"pre_order":          false,
		"current_balance":    money("0"),
		"post_balance":       money("0"),
		"payment_amount": map[string]any{
			"price":        map[string]any{"regular_price": regular},
			"total_amount": money("Free"),
			"tax_amount":   money("0"),
		},
	}})
}
