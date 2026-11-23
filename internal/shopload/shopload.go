// Package shopload builds the shop (catalog, CIA cache, artwork, archive) from an eshopd config, the same way
// for eshop-sniff and shop-preview.
package shopload

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"homebrew-eshop/internal/archive"
	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/ciacache"
	"homebrew-eshop/internal/config"
	"homebrew-eshop/internal/sniff"
	"homebrew-eshop/internal/sources"
)

// Load builds the catalog and keeps it refreshed in the background. The first build uses the sources (or their
// cache), so the shop has titles from the first request.
func Load(path string) (*sniff.Shop, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	srcs, err := sources.FromConfig(cfg, sources.Options{Client: &http.Client{Timeout: 60 * time.Second}, GitHubToken: cfg.GitHubToken})
	if err != nil {
		return nil, err
	}
	store := catalog.NewStore(srcs, cfg.CacheDir, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	store.Refresh(context.Background())
	go store.Run(context.Background(), cfg.RefreshInterval)
	n := 0
	for _, t := range store.Titles() {
		if t.CIA != nil {
			n++
		}
	}
	fmt.Printf("catalog loaded, %d installable titles\n", n)
	cias := &ciacache.Cache{Dir: filepath.Join(cfg.CacheDir, "cia"), Client: &http.Client{Timeout: 30 * time.Minute}, GitHubToken: cfg.GitHubToken}
	shop := &sniff.Shop{Titles: store.Titles, CacheDir: "sniff-data/images", CIAs: cias, ArtDir: "art"}
	if cfg.Archive != "" {
		root := cfg.Archive
		if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(root, "~/") {
			root = filepath.Join(home, root[2:])
		}
		x, err := archive.Load(root)
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		fmt.Printf("archive loaded, %d titles in %d categories\n", len(x.Titles), len(x.Dirs))
		shop.Archive = x
	}
	return shop, nil
}
