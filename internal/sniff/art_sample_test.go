package sniff

import (
	"bytes"
	"context"
	"image/jpeg"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/config"
	"homebrew-eshop/internal/sources"
)

// Renders sample artwork from the real catalog: ART_OUT=dir go test -run TestArtSamples ./internal/sniff
func TestArtSamples(t *testing.T) {
	out := os.Getenv("ART_OUT")
	if out == "" {
		t.Skip("set ART_OUT")
	}
	cfg, err := config.Load("../../config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.CacheDir = "../../" + cfg.CacheDir
	srcs, _ := sources.FromConfig(cfg, sources.Options{})
	st := catalog.NewStore(srcs, cfg.CacheDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	st.Refresh(context.Background())
	s := &Shop{Titles: st.Titles}
	save := func(name string, rep *stubReply) {
		if rep == nil {
			t.Errorf("%s: no image", name)
			return
		}
		os.WriteFile(filepath.Join(out, name+".jpg"), rep.body, 0o644)
	}
	dirs := s.dirs()
	for _, d := range dirs[:min(3, len(dirs))] {
		save("dirbanner-"+Slug(d.name), s.image("/dirbanner/"+itoa(d.id)+".jpg"))
		save("dirtile-"+Slug(d.name), s.image("/dir/"+itoa(d.id)+".jpg"))
	}
	// generated title banners, for titles with no banner art of their own
	n := 0
	for _, tt := range dirs[0].titles {
		if tt.IconURL == "" || n == 2 {
			continue
		}
		tt := tt
		var buf bytes.Buffer
		jpeg.Encode(&buf, titleBanner(&tt, s.titleIcon(&tt)), nil)
		save("titlebanner-"+Slug(tt.Name), &stubReply{body: buf.Bytes()})
		n++
	}
}
