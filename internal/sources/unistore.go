package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"homebrew-eshop/internal/catalog"
)

// UniStore reads a Universal-Updater store (.unistore), the format Universal-DB and most other homebrew stores use.
type UniStore struct {
	base
	URL     string
	MetaURL string // optional, see config.Source.MetaURL
	client  *http.Client
}

func (u *UniStore) Fetch(ctx context.Context) ([]catalog.Title, error) {
	data, err := getJSONBody(ctx, u.client, u.URL, nil)
	if err != nil {
		return nil, err
	}
	titles, err := ParseUniStore(data)
	if err != nil || u.MetaURL == "" {
		return titles, err
	}
	meta, err := getJSONBody(ctx, u.client, u.MetaURL, nil)
	if err != nil {
		return nil, fmt.Errorf("meta_url: %w", err)
	}
	if err := AddImages(titles, meta); err != nil {
		return nil, fmt.Errorf("meta_url: %w", err)
	}
	return titles, nil
}

// AddImages fills IconURL and BannerURL from a Universal-DB style full.json (a list of {title, icon, image}),
// matching apps by name.
func AddImages(titles []catalog.Title, meta []byte) error {
	var entries []struct {
		Title string `json:"title"`
		Icon  string `json:"icon"`
		Image string `json:"image"`
	}
	if err := json.Unmarshal(meta, &entries); err != nil {
		return err
	}
	byName := map[string]int{}
	for i, e := range entries {
		byName[strings.ToLower(strings.TrimSpace(e.Title))] = i
	}
	for i := range titles {
		if j, ok := byName[strings.ToLower(strings.TrimSpace(titles[i].Name))]; ok {
			if isHTTP(entries[j].Icon) {
				titles[i].IconURL = entries[j].Icon
			}
			if isHTTP(entries[j].Image) {
				titles[i].BannerURL = entries[j].Image
			}
		}
	}
	return nil
}

func isHTTP(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

type uniStoreFile struct {
	StoreInfo struct {
		Title   string `json:"title"`
		Version int    `json:"version"`
	} `json:"storeInfo"`
	StoreContent []map[string]json.RawMessage `json:"storeContent"`
}

type uniInfo struct {
	Title       string     `json:"title"`
	Author      string     `json:"author"`
	Description string     `json:"description"`
	Category    stringList `json:"category"`
	Console     stringList `json:"console"`
	Version     string     `json:"version"`
	License     string     `json:"license"`
	LastUpdated string     `json:"last_updated"`
	TitleIDs    []flexUint `json:"title_ids"`
	Screenshots []struct {
		Description string `json:"description"`
		URL         string `json:"url"`
	} `json:"screenshots"`
}

type uniStep struct {
	Type   string `json:"type"`
	File   string `json:"file"`
	Output string `json:"output"`
	Input  string `json:"input"`
	Repo   string `json:"repo"`
	Old    string `json:"old"`
	New    string `json:"new"`
}

// ParseUniStore converts a .unistore file. Entries not marked for the 3DS are skipped.
func ParseUniStore(data []byte) ([]catalog.Title, error) {
	var f uniStoreFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("unistore: %w", err)
	}
	if f.StoreContent == nil {
		return nil, fmt.Errorf("unistore: no storeContent")
	}
	var out []catalog.Title
	for _, entry := range f.StoreContent {
		var info uniInfo
		if raw, ok := entry["info"]; !ok {
			continue
		} else if err := json.Unmarshal(raw, &info); err != nil {
			continue // one malformed entry shouldn't sink the whole store
		}
		if info.Title == "" || !is3DS(info.Console) {
			continue
		}
		t := catalog.Title{
			Name:        info.Title,
			Author:      info.Author,
			Description: info.Description,
			Categories:  info.Category,
			Version:     info.Version,
			License:     info.License,
			Updated:     info.LastUpdated,
		}
		if len(info.TitleIDs) > 0 {
			t.TitleID = catalog.HomebrewTitleID(uint32(info.TitleIDs[0]))
		}
		for _, s := range info.Screenshots {
			if s.URL != "" {
				t.Screenshots = append(t.Screenshots, catalog.Screenshot{Description: s.Description, URL: s.URL})
			}
		}
		t.CIA, t.Size = pickCIA(entry)
		out = append(out, t)
	}
	return out, nil
}

func is3DS(consoles []string) bool {
	if len(consoles) == 0 {
		return true
	}
	for _, c := range consoles {
		if strings.EqualFold(c, "3ds") {
			return true
		}
	}
	return false
}

// pickCIA looks through an entry's downloads for one whose script installs a CIA, preferring stable
// downloads named *.cia. It returns where that CIA comes from and the download's listed size.
func pickCIA(entry map[string]json.RawMessage) (*catalog.CIASource, string) {
	names := make([]string, 0, len(entry))
	for k := range entry {
		if k != "info" {
			names = append(names, k)
		}
	}
	rank := func(n string) int {
		l := strings.ToLower(n)
		r := 0
		if !strings.HasSuffix(l, ".cia") {
			r += 2
		}
		if strings.Contains(l, "nightly") || strings.Contains(l, "prerelease") || strings.Contains(l, "beta") {
			r++
		}
		return r
	}
	sort.Slice(names, func(i, j int) bool {
		if ri, rj := rank(names[i]), rank(names[j]); ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		steps, size := parseDownload(entry[n])
		if cia := resolveCIA(steps); cia != nil {
			return cia, size
		}
	}
	return nil, ""
}

// parseDownload accepts both download shapes: {"script": [...], "size": "..."} (store version 3) and a bare
// step list (older stores).
func parseDownload(raw json.RawMessage) ([]uniStep, string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		var steps []uniStep
		if json.Unmarshal(raw, &steps) == nil {
			return steps, ""
		}
		return nil, ""
	}
	var d struct {
		Script []uniStep `json:"script"`
		Size   string    `json:"size"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return nil, ""
	}
	return d.Script, d.Size
}

// resolveCIA follows a script's file moves to find where the CIA passed to installCia came from. It only
// models the steps that matter for that (downloads, extraction, moves); anything else is ignored.
func resolveCIA(steps []uniStep) *catalog.CIASource {
	files := map[string]catalog.CIASource{}
	norm := func(p string) string { return strings.TrimPrefix(strings.TrimPrefix(p, "sdmc:"), "/") }
	for _, s := range steps {
		switch s.Type {
		case "downloadFile":
			if s.File != "" && s.Output != "" {
				files[norm(s.Output)] = catalog.CIASource{URL: s.File}
			}
		case "downloadRelease":
			if s.Repo != "" && s.File != "" && s.Output != "" {
				files[norm(s.Output)] = catalog.CIASource{Repo: s.Repo, Asset: s.File}
			}
		case "extractFile":
			// Only a single level of archive is supported, and only when the step names one file.
			if src, ok := files[norm(s.File)]; ok && src.Member == "" && s.Input != "" {
				src.Member = s.Input
				files[norm(s.Output)] = src
			}
		case "move":
			if src, ok := files[norm(s.Old)]; ok {
				files[norm(s.New)] = src
			}
		case "installCia":
			if src, ok := files[norm(s.File)]; ok {
				return &src
			}
		}
	}
	return nil
}

// stringList decodes either "x" or ["x", "y"].
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*l = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

// flexUint decodes a number or a string ("875533" or "0xD5C0D").
type flexUint uint64

func (u *flexUint) UnmarshalJSON(b []byte) error {
	var n uint64
	if json.Unmarshal(b, &n) == nil {
		*u = flexUint(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	n, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return err
	}
	*u = flexUint(n)
	return nil
}
