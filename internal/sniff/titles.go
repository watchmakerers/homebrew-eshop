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
	ninjaPurchase    = regexp.MustCompile(`^/ninja/ws/([A-Za-z]{2})/title/([0-9]+)/!purchase$`)
	sizeRe           = regexp.MustCompile(`^\s*([0-9.]+)\s*([KMG]i?B|B)?`)
)

// countryCurrencies maps the shop's two-letter country to its currency (currencies is keyed by region).
var countryCurrencies = map[string]string{"JP": "JPY", "US": "USD", "CA": "CAD", "GB": "GBP", "AU": "AUD", "KR": "KRW", "TW": "TWD", "HK": "HKD", "CN": "CNY",
	"DE": "EUR", "FR": "EUR", "IT": "EUR", "ES": "EUR", "NL": "EUR"}

// find returns the installable title with this shop ID.
//
// An archived title's ID finds the user's backup of it, so its archive page can be downloaded too.
func (s *Shop) find(id int) *catalog.Title {
	for _, t := range s.Titles() {
		if t.CIA != nil && ShopID(t) == id {
			t := t
			return &t
		}
	}
	if at := s.archiveTitle(int64(id)); at != nil {
		return s.ownedBackup(at)
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
	page := map[string]any{
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
	}
	if a := s.backupArchive(t); a != nil {
		if shots := archiveScreenshots(base, a); shots != nil {
			page["screenshots"] = shots
		}
	}
	return jsonReply(fmt.Sprintf("samurai title %d (%s)", id, t.Name), map[string]any{"title": page})
}

// ecInfo tells the eShop what it would download: title ID, version and size.
func (s *Shop) ecInfo(id int) *stubReply {
	t := s.find(id)
	if at := s.archiveTitle(int64(id)); t == nil && at != nil {
		if owned := s.ownedBackup(at); owned != nil {
			t = owned
		} else {
			// The page asks for this even though the title can't be bought (online_prices says
			// sales_termination); without a reply it shows 007-2404. The archive has no 3DS title IDs, so this is a
			// placeholder in an unused range that can't match an installed game.
			return jsonReply(fmt.Sprintf("ninja ec_info %d (archive: %s, not sold)", id, at.Name), map[string]any{"title_ec_info": map[string]any{
				"title_id":      fmt.Sprintf("%016X", archivePlaceholderTID(id)),
				"title_version": 0,
				"content_size":  0,
			}})
		}
	}
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

// archivePlaceholderTID is a stand-in 3DS title ID for an archived title (unique ID 0xF8000-0xFFFFF, a range no
// published title uses).
func archivePlaceholderTID(id int) uint64 {
	return 0x0004000000000000 | uint64(0xF8000|id&0x7FFF)<<8
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
			if at := s.archiveTitle(id); at != nil && s.ownedBackup(at) == nil { // the old catalog: no longer sold
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

// prepurchaseInfo is the eShop app's check before "buying" (downloading) a title. Layout from its parser
// (TIGER 0x331ec0), which walks key paths from the table at 0x3b3954:
//
//	prepurchase_info.current_balance.raw_value                  optional
//	prepurchase_info.purchasing_content                         required
//	  payment_amount.price.pre_order                            bool
//	  payment_amount.tax_amount.raw_value / total_amount.raw_value
//	  payment_amount.price.regular_price.{id,raw_value}
//	  payment_amount.price.{coupon_price,discount_price}.raw_value, conditional_prices.conditional_price  optional
//	prepurchase_info.tax_excluded                               bool
//
// Everything is free.
func (s *Shop) prepurchaseInfo(country string, id int) *stubReply {
	t := s.find(id)
	if t == nil {
		return nil
	}
	money := moneyIn(country)
	regular := money("Free")
	regular["id"] = 1
	return jsonReply(fmt.Sprintf("ninja prepurchase_info %d (%s)", id, t.Name), map[string]any{"prepurchase_info": map[string]any{
		"current_balance": money("0"),
		"tax_excluded":    false,
		"purchasing_content": map[string]any{
			"payment_amount": map[string]any{
				"price":        map[string]any{"pre_order": false, "regular_price": regular},
				"tax_amount":   money("0"),
				"total_amount": money("Free"),
			},
		},
	}})
}

// moneyIn makes samurai/ninja amounts ({amount, currency, raw_value}) in a country's currency, all zero.
func moneyIn(country string) func(amount string) map[string]any {
	currency := countryCurrencies[strings.ToUpper(country)]
	if currency == "" {
		currency = "USD"
	}
	return func(amount string) map[string]any {
		return map[string]any{"amount": amount, "currency": currency, "raw_value": "0"}
	}
}
