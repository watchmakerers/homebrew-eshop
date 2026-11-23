package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/cia"
)

// Local lists the .cia files in a folder. The title ID, and the name and publisher when the CIA has an SMDH,
// are read from each CIA. A sidecar next to it overrides them:
// MyApp.cia + MyApp.json with {"name", "author", "description", "categories", "version"}.
//
// With Backups set, the folder holds the user's own dumps of games they own (type "backups" in the config), and
// its titles are marked Backup.
type Local struct {
	base
	Dir     string
	Backups bool
}

type localMeta struct {
	Name        string   `json:"name"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
	Version     string   `json:"version"`
}

func (l *Local) Fetch(ctx context.Context) ([]catalog.Title, error) {
	dir, err := filepath.Abs(l.Dir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []catalog.Title
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".cia") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := filepath.Join(dir, e.Name())
		stem := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		t, err := localTitle(p, stem, l.Backups)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func localTitle(ciaPath, stem string, backup bool) (catalog.Title, error) {
	f, err := os.Open(ciaPath)
	if err != nil {
		return catalog.Title{}, err
	}
	defer f.Close()
	c, err := cia.Parse(f)
	if err != nil {
		return catalog.Title{}, fmt.Errorf("%s: %w", ciaPath, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return catalog.Title{}, err
	}

	t := catalog.Title{Name: stem, TitleID: c.TitleID, Size: humanSize(fi.Size()), CIA: &catalog.CIASource{Path: ciaPath}, Backup: backup}
	t.ProductCode = c.ProductCode()
	if c.TitleVersion != 0 {
		t.Version = fmt.Sprintf("v%d", c.TitleVersion)
	}
	if c.SMDH != nil {
		// English, then Japanese, then whatever the SMDH has.
		if n := c.SMDH.Title(1, 0); n.Short != "" {
			t.Name, t.Author = n.Short, n.Publisher
			if n.Long != "" && n.Long != n.Short {
				t.Description = n.Long
			}
		}
	}
	side := filepath.Join(filepath.Dir(ciaPath), stem+".json")
	if data, err := os.ReadFile(side); err == nil {
		var m localMeta
		if err := json.Unmarshal(data, &m); err != nil {
			return catalog.Title{}, fmt.Errorf("%s: %w", side, err)
		}
		if m.Name != "" {
			t.Name = m.Name
		}
		str := func(dst *string, v string) {
			if v != "" {
				*dst = v
			}
		}
		str(&t.Author, m.Author)
		str(&t.Description, m.Description)
		str(&t.Version, m.Version)
		if len(m.Categories) > 0 {
			t.Categories = m.Categories
		}
	} else if !os.IsNotExist(err) {
		return catalog.Title{}, err
	}
	return t, nil
}
