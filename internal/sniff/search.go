package sniff

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"homebrew-eshop/internal/archive"
	"homebrew-eshop/internal/catalog"
)

// search answers samurai's "contents" list, which the eShop's search screen asks for with freeword=, genre[]=,
// sort=new|popular|score, limit and offset (TIGER's URL builder). It searches the installable homebrew and
// backups first, then the archived catalog, by name and publisher; genre filters aren't applied.
func (s *Shop) search(samuraiHost string, q url.Values) *stubReply {
	words := strings.Fields(fold(q.Get("freeword")))
	match := func(fields ...string) (bool, int) {
		if len(words) == 0 {
			return true, 0
		}
		hay := fold(strings.Join(fields, " "))
		name := fold(fields[0])
		for _, w := range words {
			if !strings.Contains(hay, w) {
				return false, 0
			}
		}
		score := 1
		if strings.HasPrefix(name, words[0]) {
			score = 2
		}
		return true, score
	}

	type hit struct {
		score int
		date  string
		home  *catalog.Title
		arch  *archive.Title
	}
	var hits []hit
	for _, t := range s.Titles() {
		if t.CIA == nil {
			continue
		}
		if ok, sc := match(t.Name, t.Author); ok {
			t := t
			hits = append(hits, hit{score: sc + 10, date: releaseDate(t.Updated), home: &t})
		}
	}
	if s.Archive != nil {
		for _, t := range s.Archive.Titles {
			if ok, sc := match(t.Name, t.Publisher); ok {
				hits = append(hits, hit{score: sc, date: t.Released, arch: t})
			}
		}
	}
	byNew := q.Get("sort") == "new"
	sort.SliceStable(hits, func(i, j int) bool {
		if byNew && hits[i].date != hits[j].date {
			return hits[i].date > hits[j].date
		}
		return hits[i].score > hits[j].score
	})

	offset, limit := queryInt(q, "offset", 0), queryInt(q, "limit", 20)
	page := hits[min(offset, len(hits)):min(offset+max(limit, 0), len(hits))]
	base := imgBase(samuraiHost)
	content := make([]map[string]any, 0, len(page))
	for i, h := range page {
		var title map[string]any
		if h.home != nil {
			title = homebrewSummary(base, h.home)
		} else {
			title = archiveTitleSummary(base, h.arch, s.ownedBackup(h.arch) != nil)
		}
		content = append(content, map[string]any{"index": offset + i + 1, "title": title})
	}
	return jsonReply(fmt.Sprintf("samurai contents (search %q: %d of %d)", q.Get("freeword"), len(page), len(hits)),
		map[string]any{"contents": map[string]any{"content": content, "length": len(content), "offset": offset, "total": len(hits)}})
}

// fold lowercases and drops marks like ™ and ®, so "pokemon" finds "Pokémon™".
func fold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case 'é', 'è', 'ê', 'ë':
			r = 'e'
		case 'á', 'à', 'â', 'ä':
			r = 'a'
		case 'ó', 'ô', 'ö':
			r = 'o'
		case 'ú', 'ü':
			r = 'u'
		case 'í', 'ï':
			r = 'i'
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' {
			b.WriteRune(r)
		} else if r == '-' || r == ':' || r == '\n' {
			b.WriteRune(' ')
		}
	}
	return b.String()
}
