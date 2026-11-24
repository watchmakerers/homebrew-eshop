// Package config loads the server's YAML config, most importantly the list of catalog sources.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen          string        `yaml:"listen"`
	CacheDir        string        `yaml:"cache_dir"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	// GitHub API token for `github` sources (optional; raises the 60 requests/hour limit). GITHUB_TOKEN overrides it.
	GitHubToken string   `yaml:"github_token"`
	Sources     []Source `yaml:"sources"`
	// Archive is a saved copy of Nintendo's 3DS samurai server and its images (a Wayback Machine download laid
	// out by host/path), shown browse-only after the homebrew. Optional; "~/" is expanded.
	Archive string `yaml:"archive"`
}

// Source is one entry under `sources:`. Which fields apply depends on Type.
type Source struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"` // unistore | github | local | backups | web
	Priority int    `yaml:"priority"`
	Enabled  *bool  `yaml:"enabled"` // default true

	URL string `yaml:"url"` // unistore; web: the page whose .cia links to list
	// unistore, optional: Universal-DB's full.json (or anything shaped like it), for icon and banner image
	// links, which .unistore files don't have (their icons are packed in a 3DS texture sheet).
	MetaURL string `yaml:"meta_url"`

	Repo         string `yaml:"repo"`          // github: owner/name
	AssetPattern string `yaml:"asset_pattern"` // github: glob for the release asset, default *.cia

	Path string `yaml:"path"` // local, backups: folder of .cia files

	// web only: Depth follows links to sub-folders below url that many levels (default 0, just the page);
	// Backups marks the CIAs as your own dumps of games you own, like a "backups" folder.
	Depth   int  `yaml:"depth"`
	Backups bool `yaml:"backups"`

	// github only: metadata GitHub doesn't have. Title defaults to the repo name.
	TitleID     string   `yaml:"title_id"` // hex, e.g. 000400000D5C0D00
	Title       string   `yaml:"title"`
	Author      string   `yaml:"author"`
	Description string   `yaml:"description"`
	Categories  []string `yaml:"categories"`
}

func (s Source) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// ParseTitleID parses a 16-digit hex title ID (an optional 0x prefix is allowed).
func ParseTitleID(s string) (uint64, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	if len(s) != 16 {
		return 0, fmt.Errorf("title ID %q must be 16 hex digits", s)
	}
	return strconv.ParseUint(s, 16, 64)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // catch typos like `asset_patern`
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = "cache"
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 6 * time.Hour
	}
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		cfg.GitHubToken = t
	}
	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	if c.RefreshInterval < time.Minute {
		return fmt.Errorf("config: refresh_interval %s is under a minute", c.RefreshInterval)
	}
	seen := map[string]bool{}
	for i, s := range c.Sources {
		where := fmt.Sprintf("config: sources[%d] (%s)", i, s.Name)
		if s.Name == "" {
			return fmt.Errorf("config: sources[%d] has no name", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("%s: duplicate name", where)
		}
		seen[s.Name] = true
		var missing string
		switch s.Type {
		case "unistore", "web":
			if s.URL == "" {
				missing = "url"
			}
		case "github":
			if s.Repo == "" || strings.Count(s.Repo, "/") != 1 {
				return fmt.Errorf("%s: repo must be owner/name", where)
			}
			if s.TitleID != "" {
				if _, err := ParseTitleID(s.TitleID); err != nil {
					return fmt.Errorf("%s: %w", where, err)
				}
			}
		case "local", "backups":
			if s.Path == "" {
				missing = "path"
			}
		default:
			return fmt.Errorf("%s: unknown type %q (want unistore, github, local, backups or web)", where, s.Type)
		}
		if missing != "" {
			return fmt.Errorf("%s: type %s needs %s", where, s.Type, missing)
		}
	}
	return nil
}
