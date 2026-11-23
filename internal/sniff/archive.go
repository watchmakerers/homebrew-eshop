package sniff

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"regexp"
	"strconv"
	"strings"

	"homebrew-eshop/internal/archive"
	"homebrew-eshop/internal/catalog"
)

// The archived 3DS catalog (see package archive), shown after the homebrew categories as browse-only pages:
// nothing in it can be bought or downloaded, and its prices report the shop's real end state,
// "sales_termination". It uses the archive's own IDs, which are far above homebrew shop IDs (ShopID is < 2^30).

// archiveAllID is the "Nintendo eShop Archive" category holding every archived title.
const archiveAllID = 200

type archiveDir struct {
	id     int64
	name   string
	dir    *archive.Dir // nil for archiveAllID
	titles []*archive.Title
}

// archiveRule says which archived titles belong in an archived category. Categories without a rule (sales,
// Switch adverts, lists whose contents weren't archived) are left out.
type archiveRule func(t *archive.Title) bool

func nameHas(words ...string) archiveRule {
	return func(t *archive.Title) bool {
		n := strings.ToLower(t.Name)
		for _, w := range words {
			if strings.Contains(n, w) {
				return true
			}
		}
		return false
	}
}

func genreHas(words ...string) archiveRule {
	return func(t *archive.Title) bool {
		for _, g := range strings.Split(t.Genre, "/") {
			for _, w := range words {
				if strings.EqualFold(strings.TrimSpace(g), w) {
					return true
				}
			}
		}
		return false
	}
}

func platformIs(names ...string) archiveRule {
	return func(t *archive.Title) bool {
		for _, n := range names {
			if t.Platform == n {
				return true
			}
		}
		return false
	}
}

// archiveRules is keyed by the category's name, lowercased, with spaces and punctuation removed (see ruleKey).
var archiveRules = map[string]archiveRule{
	"pokémon":                            nameHas("pokémon", "pokemon"),
	"mario":                              nameHas("mario"),
	"animalcrossingnewleafwelcomeamiibo": nameHas("animal crossing"),
	"thelegendofzelda":                   nameHas("zelda"),
	"fireemblemsaga":                     nameHas("fire emblem"),
	"kirby":                              nameHas("kirby"),
	"sonic":                              nameHas("sonic"),
	"donkeykong":                         nameHas("donkey kong"),
	"supersmashbrosfornintendo3ds":       nameHas("smash bros"),
	"minecraftnewnintendo3dsedition":     nameHas("minecraft"),
	"metroidsamusreturns":                nameHas("metroid"),
	"epicrpgs":                           genreHas("RPG"),
	"strategygames":                      genreHas("Strategy"),
	"applications":                       genreHas("Application", "Utility", "Communication", "Lifestyle"),
	"virtualconsole":                     platformIs("NES", "Super NES", "Game Boy", "Game Boy Color", "Game Boy Advance", "Game Gear", "TurboGrafx-16"),
	"demos":                              func(t *archive.Title) bool { return t.Demo },
	"nintendo3dsdownload":                platformIs("Nintendo 3DS Download Only", "New 3DS Download Only"),
	"nintendo3dscarddownload":            platformIs("Nintendo 3DS Retail/Download", "New 3DS Retail/Download"),
	"dsiware":                            platformIs("Nintendo DSiWare"),
}

var ruleKeyRe = regexp.MustCompile(`[\s\p{P}™®©]+`)

func ruleKey(name string) string { return ruleKeyRe.ReplaceAllString(strings.ToLower(name), "") }

// archiveDirs lists the archive's categories that have titles, then the all-titles one.
func (s *Shop) archiveDirs() []archiveDir {
	x := s.Archive
	if x == nil || len(x.Titles) == 0 {
		return nil
	}
	var out []archiveDir
	seen := map[string]bool{}
	for _, d := range x.Dirs {
		key := ruleKey(d.Name)
		rule := archiveRules[key]
		if rule == nil || seen[key] {
			continue
		}
		var ts []*archive.Title
		for _, t := range x.Titles {
			if rule(t) {
				ts = append(ts, t)
			}
		}
		if len(ts) == 0 {
			continue
		}
		seen[key] = true
		out = append(out, archiveDir{id: d.ID, name: strings.Join(strings.Fields(d.Name), " "), dir: d, titles: ts})
	}
	return append(out, archiveDir{id: archiveAllID, name: "Nintendo eShop Archive", titles: x.Titles})
}

func (s *Shop) archiveDir(id int64) *archiveDir {
	for _, d := range s.archiveDirs() {
		if d.id == id {
			d := d
			return &d
		}
	}
	return nil
}

func (s *Shop) archiveTitle(id int64) *archive.Title {
	if s.Archive == nil || id < 1<<30 {
		return nil
	}
	return s.Archive.Title(id)
}

// archiveDirEntries is what directories() adds for the archive.
func (s *Shop) archiveDirEntries(samuraiHost string) []map[string]any {
	var list []map[string]any
	base := imgBase(samuraiHost)
	for _, d := range s.archiveDirs() {
		list = append(list, map[string]any{
			"id": d.id, "index": d.id, "name": d.name, "type": "normal", "standard": true, "new": false,
			"icon_url":   fmt.Sprintf("%s/dir/%d.jpg", base, d.id),
			"icon_width": 128, "icon_height": 96, "banner_url": fmt.Sprintf("%s/dirbanner/%d.jpg", base, d.id),
		})
	}
	return list
}

func (s *Shop) archiveDirectory(samuraiHost string, d *archiveDir, q map[string][]string) *stubReply {
	offset, limit := queryInt(q, "offset", 0), queryInt(q, "limit", len(d.titles))
	page := d.titles[min(offset, len(d.titles)):min(offset+max(limit, 0), len(d.titles))]
	base := imgBase(samuraiHost)
	content := make([]map[string]any, 0, len(page))
	for i, t := range page {
		content = append(content, map[string]any{"index": offset + i + 1, "title": archiveTitleSummary(base, t, s.ownedBackup(t) != nil)})
	}
	return jsonReply(fmt.Sprintf("samurai directory %d (archive, %d titles)", d.id, len(page)), map[string]any{"directory": map[string]any{
		"id": d.id, "name": d.name,
		"icon_url": fmt.Sprintf("%s/dir/%d.jpg", base, d.id), "icon_width": 76, "icon_height": 58,
		"banner_url": fmt.Sprintf("%s/dirbanner/%d.jpg", base, d.id),
		"contents":   map[string]any{"content": content, "length": len(content), "offset": offset, "total": len(d.titles)},
	}})
}

func orUnknown(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

// ownedBackup is the user's own backup of an archived title, matched by game code (any region if the exact
// code isn't among the backups); nil if they have none. An owned title is downloadable from its archive page.
func (s *Shop) ownedBackup(at *archive.Title) *catalog.Title {
	code := at.GameCode()
	if code == "" {
		return nil
	}
	var other *catalog.Title
	for _, t := range s.Titles() {
		if !t.Backup || t.CIA == nil {
			continue
		}
		c := archive.GameCode(t.ProductCode)
		if c == code {
			t := t
			return &t
		}
		if other == nil && len(c) == 4 && c[:3] == code[:3] {
			t := t
			other = &t
		}
	}
	return other
}

func archiveTitleSummary(base string, t *archive.Title, owned bool) map[string]any {
	return map[string]any{
		"id":                    t.ID,
		"name":                  t.Name,
		"product_code":          t.ProductCode,
		"publisher":             map[string]any{"id": 1, "name": orUnknown(t.Publisher)},
		"display_genre":         orUnknown(t.Genre),
		"release_date_on_eshop": orDate(t.Released),
		"retail_sales":          false, "eshop_sales": owned, "demo_available": false,
		"aoc_available": false, "in_app_purchase": false, "new": false,
		"icon_url":   fmt.Sprintf("%s/icon/%d.jpg", base, t.ID),
		"banner_url": fmt.Sprintf("%s/banner/%d.jpg", base, t.ID),
	}
}

func orDate(d string) string {
	if d == "" {
		return "2011-02-26"
	}
	return d
}

func (s *Shop) archiveTitlePage(samuraiHost string, t *archive.Title) *stubReply {
	desc := t.Description
	if desc == "" {
		desc = t.Name
	}
	owned := s.ownedBackup(t)
	page := archiveTitleSummary(imgBase(samuraiHost), t, owned != nil)
	page["formal_name"] = t.Name
	page["description"] = desc
	page["disclaimer"] = "From the archived Nintendo eShop catalog. No longer sold; shown for reference only."
	if owned != nil {
		page["disclaimer"] = "You own this: downloading installs your own backup from your PC."
		tid := titleID(owned)
		if info, err := s.prepareFor(owned, pageWait); err == nil {
			tid = info.titleID
		}
		page["title_id"] = fmt.Sprintf("%016X", tid)
	}
	page["genres"] = map[string]any{"genre": []map[string]any{{"id": 1, "name": orUnknown(t.Genre)}}, "length": 1}
	page["languages"] = map[string]any{"language": []map[string]any{{"iso_code": "en", "name": "English"}}}
	page["number_of_players"] = "1"
	page["title_version"] = 0
	page["ticket_available"] = false
	page["downloadable"] = owned != nil
	page["movie_available"] = false
	if shots := archiveScreenshots(imgBase(samuraiHost), t); shots != nil {
		page["screenshots"] = shots
	}
	return jsonReply(fmt.Sprintf("samurai title %d (archive: %s)", t.ID, t.Name), map[string]any{"title": page})
}

// archiveImage serves an archived title's or category's original image, unchanged. ok is false when the
// ID isn't the archive's; a nil reply with ok means the archive has no such image (the caller falls back).
func (s *Shop) archiveImage(kind string, id int64) (reply *stubReply, ok bool) {
	if s.Archive == nil || id < archiveAllID {
		return nil, false
	}
	var path string
	switch kind {
	case "icon", "banner":
		t := s.archiveTitle(id)
		if t == nil {
			return nil, false
		}
		if path = t.Icon; kind == "banner" {
			path = t.Banner
		}
	case "dir", "dirbanner":
		d := s.archiveDir(id)
		if d == nil {
			return nil, false
		}
		if d.dir == nil { // the all-titles category: user art, else generated from the newest icons
			return s.archiveAllArt(kind, d), true
		}
		if path = d.dir.Icon; kind == "dirbanner" {
			path = d.dir.Banner
		}
		if path == "" {
			return s.generatedArchiveDirArt(kind, d), true
		}
	}
	if b := archive.ReadImage(path); b != nil {
		return &stubReply{name: fmt.Sprintf("image archive %s %d", kind, id), contentType: "image/jpeg", body: b}, true
	}
	return nil, true
}

func (s *Shop) archiveIcons(ts []*archive.Title, n int) []image.Image {
	var out []image.Image
	for _, t := range ts {
		if len(out) >= n {
			break
		}
		if b := archive.ReadImage(t.Icon); b != nil {
			if img, _, err := image.Decode(bytes.NewReader(b)); err == nil {
				out = append(out, img)
			}
		}
	}
	return out
}

func (s *Shop) archiveAllArt(kind string, d *archiveDir) *stubReply {
	slug := Slug(d.name)
	if kind == "dir" {
		if u := s.userArt("categories", slug+"-tile"); u != nil {
			return jpegReply("image archive dir (user)", fit(u, 128, 96))
		}
	} else if u := s.userArt("categories", slug); u != nil {
		return jpegReply("image archive dirbanner (user)", fit(u, 400, 240))
	}
	return s.generatedArchiveDirArt(kind, d)
}

func (s *Shop) generatedArchiveDirArt(kind string, d *archiveDir) *stubReply {
	sd := shopDir{id: int(d.id % 1000), name: d.name}
	if kind == "dir" {
		return jpegReply("image archive dir (generated)", dirTile(sd, s.archiveIcons(d.titles, 4)))
	}
	return jpegReply("image archive dirbanner (generated)", dirBanner(sd, s.archiveIcons(d.titles, 3)))
}

func jpegReply(name string, img image.Image) *stubReply {
	var buf bytes.Buffer
	if jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}) != nil {
		return nil
	}
	return &stubReply{name: name, contentType: "image/jpeg", body: buf.Bytes()}
}

// backupArchive finds the archived listing for one of the user's own backups, by its game code.
func (s *Shop) backupArchive(t *catalog.Title) *archive.Title {
	if s.Archive == nil || !t.Backup || t.ProductCode == "" {
		return nil
	}
	return s.Archive.ByGameCode(archive.GameCode(t.ProductCode))
}

// archiveScreenshots is a title page's "screenshots" in the layout the eShop reads (TIGER 0x243030):
// {"screenshot": [{"image_url": [{"type": "upper", "value": url}, {"type": "lower", "value": url}]}]}.
func archiveScreenshots(base string, t *archive.Title) map[string]any {
	var list []map[string]any
	for i, sh := range t.Screenshots {
		var urls []map[string]any
		for _, side := range []struct{ name, path string }{{"upper", sh.Upper}, {"lower", sh.Lower}} {
			if side.path != "" {
				urls = append(urls, map[string]any{"type": side.name, "value": fmt.Sprintf("%s/shot/%d/%d/%s.jpg", base, t.ID, i, side.name)})
			}
		}
		list = append(list, map[string]any{"image_url": urls})
	}
	if list == nil {
		return nil
	}
	return map[string]any{"screenshot": list}
}

var shotPath = regexp.MustCompile(`^/shot/([0-9]+)/([0-9]+)/(upper|lower)\.jpg$`)

// archiveShot serves an archived screenshot as-is.
func (s *Shop) archiveShot(path string) *stubReply {
	m := shotPath.FindStringSubmatch(path)
	if m == nil || s.Archive == nil {
		return nil
	}
	id, _ := strconv.ParseInt(m[1], 10, 64)
	n, _ := strconv.Atoi(m[2])
	t := s.Archive.Title(id)
	if t == nil || n >= len(t.Screenshots) {
		return nil
	}
	p := t.Screenshots[n].Upper
	if m[3] == "lower" {
		p = t.Screenshots[n].Lower
	}
	if b := archive.ReadImage(p); b != nil {
		return &stubReply{name: "image archive screenshot " + m[1], contentType: "image/jpeg", body: b}
	}
	return nil
}
