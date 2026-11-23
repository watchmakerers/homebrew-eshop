package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/config"
)

// GitHub lists one app from a repo's latest release, for apps that aren't in any store.
type GitHub struct {
	base
	Repo         string
	AssetPattern string
	meta         catalog.Title // title/author/description/categories/title ID from the config
	client       *http.Client
	api, token   string
}

func newGitHub(b base, s config.Source, opt Options) (*GitHub, error) {
	g := &GitHub{
		base: b, Repo: s.Repo, AssetPattern: s.AssetPattern,
		client: opt.Client, api: strings.TrimSuffix(opt.GitHubAPI, "/"), token: opt.GitHubToken,
		meta: catalog.Title{Name: s.Title, Author: s.Author, Description: s.Description, Categories: s.Categories},
	}
	if g.AssetPattern == "" {
		g.AssetPattern = "*.cia"
	}
	if _, err := path.Match(g.AssetPattern, ""); err != nil {
		return nil, fmt.Errorf("source %s: asset_pattern: %w", s.Name, err)
	}
	if s.TitleID != "" {
		id, err := config.ParseTitleID(s.TitleID)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.Name, err)
		}
		g.meta.TitleID = id
	}
	return g, nil
}

type ghRepo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Owner       struct {
		Login string `json:"login"`
	} `json:"owner"`
	License *struct {
		SPDX string `json:"spdx_id"`
	} `json:"license"`
}

type ghRelease struct {
	TagName     string `json:"tag_name"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func (g *GitHub) Fetch(ctx context.Context) ([]catalog.Title, error) {
	var repo ghRepo
	if err := g.get(ctx, "/repos/"+g.Repo, &repo); err != nil {
		return nil, err
	}
	var rel ghRelease
	if err := g.get(ctx, "/repos/"+g.Repo+"/releases/latest", &rel); err != nil {
		return nil, err
	}

	t := g.meta
	if t.Name == "" {
		t.Name = repo.Name
	}
	if t.Author == "" {
		t.Author = repo.Owner.Login
	}
	if t.Description == "" {
		t.Description = repo.Description
	}
	if repo.License != nil && repo.License.SPDX != "NOASSERTION" {
		t.License = strings.ToLower(repo.License.SPDX)
	}
	t.Version, t.Updated = rel.TagName, rel.PublishedAt

	for _, a := range rel.Assets {
		if ok, _ := path.Match(g.AssetPattern, a.Name); ok {
			t.CIA = &catalog.CIASource{URL: a.URL}
			t.Size = humanSize(a.Size)
			break
		}
	}
	if t.CIA == nil {
		return nil, fmt.Errorf("%s %s: no release asset matches %q", g.Repo, rel.TagName, g.AssetPattern)
	}
	return []catalog.Title{t}, nil
}

func (g *GitHub) get(ctx context.Context, p string, v any) error {
	h := http.Header{"Accept": {"application/vnd.github+json"}}
	if g.token != "" {
		h.Set("Authorization", "Bearer "+g.token)
	}
	data, err := getJSONBody(ctx, g.client, g.api+p, h)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}
