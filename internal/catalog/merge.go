package catalog

import (
	"sort"
)

// SourceResult is what one source returned.
type SourceResult struct {
	Name     string
	Priority int
	Titles   []Title
}

// Merge combines all sources into one catalog. Titles with the same Key are one app: the entry from the
// highest-priority source wins (ties go to the source listed first), and fields it leaves empty are filled
// from lower-priority entries. The result is sorted by name.
func Merge(results []SourceResult) []Title {
	order := make([]SourceResult, len(results))
	copy(order, results)
	sort.SliceStable(order, func(i, j int) bool { return order[i].Priority > order[j].Priority })

	byKey := map[string]*Title{}
	var keys []string
	for _, r := range order {
		for _, t := range r.Titles {
			if t.Name == "" {
				continue
			}
			k := t.Key()
			cur, ok := byKey[k]
			if !ok {
				t := t
				t.Source, t.AlsoIn = r.Name, nil
				byKey[k] = &t
				keys = append(keys, k)
				continue
			}
			if cur.Source != r.Name && !contains(cur.AlsoIn, r.Name) {
				cur.AlsoIn = append(cur.AlsoIn, r.Name)
			}
			fillEmpty(cur, &t)
		}
	}

	out := make([]Title, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return lessFold(out[i].Name, out[j].Name) })
	return out
}

func fillEmpty(dst, src *Title) {
	str := func(d *string, s string) {
		if *d == "" {
			*d = s
		}
	}
	str(&dst.Author, src.Author)
	str(&dst.Description, src.Description)
	str(&dst.Version, src.Version)
	str(&dst.License, src.License)
	str(&dst.Updated, src.Updated)
	str(&dst.Size, src.Size)
	str(&dst.IconURL, src.IconURL)
	str(&dst.BannerURL, src.BannerURL)
	if len(dst.Categories) == 0 {
		dst.Categories = src.Categories
	}
	if len(dst.Screenshots) == 0 {
		dst.Screenshots = src.Screenshots
	}
	if dst.CIA == nil {
		dst.CIA = src.CIA
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func lessFold(a, b string) bool {
	la, lb := toLower(a), toLower(b)
	if la != lb {
		return la < lb
	}
	return a < b
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
