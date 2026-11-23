// Package sources has one adapter per `type:` in the config. Each turns its source's format into catalog.Titles.
package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/config"
)

const userAgent = "homebrew-eshop/0.1"

// Options are shared by all adapters.
type Options struct {
	Client      *http.Client
	GitHubToken string
	GitHubAPI   string // default https://api.github.com; tests point it at a fake
}

// New builds the adapter for one config entry.
func New(s config.Source, opt Options) (catalog.Source, error) {
	if opt.Client == nil {
		opt.Client = http.DefaultClient
	}
	if opt.GitHubAPI == "" {
		opt.GitHubAPI = "https://api.github.com"
	}
	base := base{name: s.Name, priority: s.Priority}
	switch s.Type {
	case "unistore":
		return &UniStore{base: base, URL: s.URL, MetaURL: s.MetaURL, client: opt.Client}, nil
	case "github":
		return newGitHub(base, s, opt)
	case "local":
		return &Local{base: base, Dir: s.Path}, nil
	case "backups":
		return &Local{base: base, Dir: s.Path, Backups: true}, nil
	}
	return nil, fmt.Errorf("source %s: unknown type %q", s.Name, s.Type)
}

// FromConfig builds every enabled source.
func FromConfig(cfg *config.Config, opt Options) ([]catalog.Source, error) {
	var out []catalog.Source
	for _, s := range cfg.Sources {
		if !s.IsEnabled() {
			continue
		}
		src, err := New(s, opt)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, nil
}

type base struct {
	name     string
	priority int
}

func (b base) Name() string  { return b.name }
func (b base) Priority() int { return b.priority }

// maxBody caps what we read from any source (Universal-DB's catalog is about 1 MB).
const maxBody = 64 << 20

func getJSONBody(ctx context.Context, client *http.Client, url string, header http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBody {
		return nil, fmt.Errorf("GET %s: response over %d bytes", url, maxBody)
	}
	return data, nil
}
