// eshopd is the homebrew eShop server. For now it builds the merged catalog from the configured sources and
// serves it on debug endpoints; the eShop protocol endpoints come next.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/config"
	"homebrew-eshop/internal/sources"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "config file")
	dump := flag.Bool("dump", false, "fetch every source once, print a summary and exit")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*cfgPath, *dump, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, dump bool, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	srcs, err := sources.FromConfig(cfg, sources.Options{
		Client:      &http.Client{Timeout: 60 * time.Second},
		GitHubToken: cfg.GitHubToken,
	})
	if err != nil {
		return err
	}
	store := catalog.NewStore(srcs, cfg.CacheDir, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if dump {
		store.Refresh(ctx)
		printSummary(store)
		return nil
	}

	go store.Run(ctx, cfg.RefreshInterval)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/catalog", func(w http.ResponseWriter, r *http.Request) {
		titles := store.Titles()
		if r.URL.Query().Get("installable") == "1" {
			titles = installable(titles)
		}
		writeJSON(w, titles)
	})
	mux.HandleFunc("GET /debug/sources", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, store.Statuses())
	})

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", cfg.Listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func installable(titles []catalog.Title) []catalog.Title {
	var out []catalog.Title
	for _, t := range titles {
		if t.CIA != nil {
			out = append(out, t)
		}
	}
	return out
}

func printSummary(store *catalog.Store) {
	for _, s := range store.Statuses() {
		state := "ok"
		switch {
		case s.FromCache:
			state = "FAILED, using cache: " + s.Error
		case s.Error != "":
			state = "FAILED: " + s.Error
		}
		fmt.Printf("%-28s %5d titles  %s\n", s.Name, s.Titles, state)
	}
	titles := store.Titles()
	withID := 0
	for _, t := range titles {
		if t.TitleID != 0 {
			withID++
		}
	}
	fmt.Printf("\nmerged: %d titles, %d installable as CIA, %d with a title ID\n", len(titles), len(installable(titles)), withID)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
