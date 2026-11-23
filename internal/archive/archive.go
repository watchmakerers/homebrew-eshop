// Package archive reads a saved copy of Nintendo's 3DS samurai server (e.g. a Wayback Machine download) so the
// shop can show the old catalog as browse-only pages with its original artwork.
//
// The folder is laid out by host and path, the way Wayback downloaders save responses:
//
//	<root>/samurai.ctr.shop.nintendo.net/samurai/ws/<country>/...   samurai replies (XML)
//	<root>/kanzashi-ctr.cdn.nintendo.net/i/<hash>.jpg                images
//
// File names don't matter: every samurai reply is scanned for <title> and <directory> elements. Only 3DS
// entries are kept (product codes CTR-/KTR-, images on kanzashi-ctr). Nothing from the archive is installable.
package archive

import (
	"encoding/xml"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Title is one 3DS title from the archive, merged from every reply that mentions it.
type Title struct {
	ID          int64 // samurai's ID (not the 3DS title ID)
	ProductCode string
	Name        string
	Publisher   string
	Genre       string // display_genre
	Platform    string
	Released    string // YYYY-MM-DD, eShop release if known, else retail
	Description string // only titles whose detail page was archived have one
	Rating      string
	Icon        string // local file, "" if the image wasn't archived
	Banner      string
	Demo        bool
	Country     string
	Screenshots []Shot // only titles whose detail page was archived
}

// Shot is one screenshot: the top and bottom screens (local files; either may be "").
type Shot struct{ Upper, Lower string }

// GameCode is the 4-character code inside the product code ("CTR-N-AJRE" -> "AJRE"), which is the same
// for a game's card and download versions and matches the code inside its CIA.
func (t *Title) GameCode() string { return GameCode(t.ProductCode) }

func GameCode(productCode string) string {
	p := strings.Split(strings.TrimSpace(productCode), "-")
	if len(p) == 3 && len(p[2]) == 4 {
		return strings.ToUpper(p[2])
	}
	return ""
}

// Dir is a 3DS category ("directory") from the archive. Its contents weren't archived, only its art.
type Dir struct {
	ID          int64
	Name        string
	Type        string // normal, search, ...
	Description string
	Icon        string // local tile image (128x96)
	Banner      string // local top-screen banner
	Country     string
}

type Index struct {
	Root   string
	Titles []*Title // sorted newest first
	Dirs   []*Dir   // in the order the shop listed them; US first

	byID   map[int64]*Title
	byCode map[string]*Title
}

func (x *Index) Title(id int64) *Title { return x.byID[id] }

// ByGameCode finds a title by the 4-character game code; nil if none.
// ByGameCode finds a title by the 4-character game code; if that exact code isn't archived, the same game from
// another region (the last letter is the region: E America, J Japan, P Europe...), preferring America's.
func (x *Index) ByGameCode(code string) *Title {
	code = strings.ToUpper(code)
	if t := x.byCode[code]; t != nil || len(code) != 4 {
		return t
	}
	var best *Title
	for c, t := range x.byCode {
		if c[:3] == code[:3] && (best == nil || c[3] == 'E' || (best.GameCode()[3] != 'E' && c < best.GameCode())) {
			best = t
		}
	}
	return best
}

func (x *Index) Dir(id int64) *Dir {
	for _, d := range x.Dirs {
		if d.ID == id {
			return d
		}
	}
	return nil
}

type xmlTitle struct {
	ID          string `xml:"id,attr"`
	ProductCode string `xml:"product_code"`
	Name        string `xml:"name"`
	FormalName  string `xml:"formal_name"`
	IconURL     string `xml:"icon_url"`
	BannerURL   string `xml:"banner_url"`
	Platform    struct {
		Name   string `xml:"name"`
		Device string `xml:"device,attr"`
	} `xml:"platform"`
	Publisher struct {
		Name string `xml:"name"`
	} `xml:"publisher"`
	Genre  string `xml:"display_genre"`
	Rating struct {
		Name string `xml:"rating>name"`
	} `xml:"rating_info"`
	EshopDate   string `xml:"release_date_on_eshop"`
	RetailDate  string `xml:"release_date_on_retail"`
	Description string `xml:"description"`
	Demo        bool   `xml:"demo_available"`
	Screenshots []struct {
		Images []struct {
			Type string `xml:"type,attr"`
			URL  string `xml:",chardata"`
		} `xml:"image_url"`
	} `xml:"screenshots>screenshot"`
}

type xmlDir struct {
	ID          string `xml:"id,attr"`
	Type        string `xml:"type,attr"`
	Name        string `xml:"name"`
	IconURL     string `xml:"icon_url"`
	BannerURL   string `xml:"banner_url"`
	Description string `xml:"description"`
}

var countryRe = regexp.MustCompile(`/samurai/ws/([A-Z]{2})/`)

// Load scans root. A missing root is an error; unreadable files are skipped.
func Load(root string) (*Index, error) {
	x := &Index{Root: root, byID: map[int64]*Title{}, byCode: map[string]*Title{}}
	ws := filepath.Join(root, "samurai.ctr.shop.nintendo.net", "samurai", "ws")
	if _, err := os.Stat(ws); err != nil {
		return nil, err
	}
	dirSeen := map[int64]bool{}
	var dirs []*Dir
	err := filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		country := ""
		if m := countryRe.FindStringSubmatch(filepath.ToSlash(p)); m != nil {
			country = m[1]
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		dec := xml.NewDecoder(f)
		dec.Strict = false
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil // EOF or not XML
			}
			se, ok := tok.(xml.StartElement)
			if !ok {
				continue
			}
			switch se.Name.Local {
			case "title":
				var t xmlTitle
				if dec.DecodeElement(&t, &se) == nil {
					x.addTitle(&t, country)
				}
			case "directory":
				var xd xmlDir
				if dec.DecodeElement(&xd, &se) != nil || !strings.Contains(xd.IconURL+xd.BannerURL, "kanzashi-ctr") {
					continue
				}
				id, _ := strconv.ParseInt(xd.ID, 10, 64)
				if id == 0 || dirSeen[id] {
					continue
				}
				dirSeen[id] = true
				dirs = append(dirs, &Dir{ID: id, Name: strings.TrimSpace(xd.Name), Type: xd.Type, Description: clean(xd.Description),
					Icon: x.local(xd.IconURL), Banner: x.local(xd.BannerURL), Country: country})
			}
		}
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(dirs, func(i, j int) bool { return dirs[i].Country == "US" && dirs[j].Country != "US" })
	x.Dirs = dirs
	for _, t := range x.byID {
		x.Titles = append(x.Titles, t)
	}
	sort.Slice(x.Titles, func(i, j int) bool {
		if x.Titles[i].Released != x.Titles[j].Released {
			return x.Titles[i].Released > x.Titles[j].Released
		}
		return x.Titles[i].ID < x.Titles[j].ID
	})
	return x, nil
}

func (x *Index) addTitle(xt *xmlTitle, country string) {
	pc := strings.TrimSpace(xt.ProductCode)
	if !strings.HasPrefix(pc, "CTR-") && !strings.HasPrefix(pc, "KTR-") {
		return
	}
	switch strings.TrimSpace(xt.Platform.Name) {
	case "Software Update", "Downloadable Video": // patches and videos aren't titles to browse
		return
	}
	id, err := strconv.ParseInt(xt.ID, 10, 64)
	if err != nil || id == 0 {
		return
	}
	t := x.byID[id]
	if t == nil {
		t = &Title{ID: id, Country: country}
		x.byID[id] = t
	}
	set := func(dst *string, v string) {
		if v = strings.TrimSpace(v); v != "" && *dst == "" {
			*dst = v
		}
	}
	set(&t.ProductCode, pc)
	name := xt.FormalName
	if name == "" {
		name = xt.Name
	}
	set(&t.Name, strings.Join(strings.Fields(name), " "))
	set(&t.Publisher, xt.Publisher.Name)
	set(&t.Genre, xt.Genre)
	set(&t.Platform, xt.Platform.Name)
	set(&t.Rating, xt.Rating.Name)
	set(&t.Released, dateRe.FindString(xt.EshopDate))
	set(&t.Released, dateRe.FindString(xt.RetailDate))
	set(&t.Description, clean(xt.Description))
	set(&t.Icon, x.local(xt.IconURL))
	set(&t.Banner, x.local(xt.BannerURL))
	t.Demo = t.Demo || xt.Demo
	if len(t.Screenshots) == 0 {
		for _, sc := range xt.Screenshots {
			var shot Shot
			for _, im := range sc.Images {
				switch im.Type {
				case "upper":
					shot.Upper = x.local(im.URL)
				case "lower":
					shot.Lower = x.local(im.URL)
				}
			}
			if shot.Upper != "" || shot.Lower != "" {
				t.Screenshots = append(t.Screenshots, shot)
			}
		}
	}
	if c := GameCode(pc); c != "" {
		if old := x.byCode[c]; old == nil || (old.Banner == "" && t.Banner != "") {
			x.byCode[c] = t
		}
	}
}

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)

var brRe = regexp.MustCompile(`(?i)\s*<br\s*/?>\s*`)

// clean turns samurai's <BR> line breaks into newlines.
func clean(s string) string {
	return strings.TrimSpace(brRe.ReplaceAllString(s, "\n"))
}

// local maps an image URL to the archived file, or "" if it isn't there.
func (x *Index) local(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	p := filepath.Join(x.Root, u.Host, filepath.FromSlash(u.Path))
	if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
		return p
	}
	return ""
}

// ReadImage returns an archived image file's bytes, or nil.
func ReadImage(path string) []byte {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil
	}
	return b
}
