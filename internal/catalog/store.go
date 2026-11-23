package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Status reports how a source did on the last refresh.
type Status struct {
	Name      string    `json:"name"`
	Titles    int       `json:"titles"`
	FetchedAt time.Time `json:"fetched_at,omitzero"` // when the titles in use were fetched
	FromCache bool      `json:"from_cache"`          // the fetch failed; using the last good copy
	Error     string    `json:"error,omitempty"`
}

// Store refreshes every source, keeps the last good copy of each (in memory and in CacheDir, so a source
// that's down at startup still has its titles), and serves the merged catalog.
type Store struct {
	sources  []Source
	cacheDir string
	timeout  time.Duration
	log      *slog.Logger

	mu       sync.RWMutex
	titles   []Title
	statuses []Status
	lastGood map[string]cached
}

type cached struct {
	FetchedAt time.Time `json:"fetched_at"`
	Titles    []Title   `json:"titles"`
}

func NewStore(sources []Source, cacheDir string, log *slog.Logger) *Store {
	return &Store{sources: sources, cacheDir: cacheDir, timeout: 2 * time.Minute, log: log, lastGood: map[string]cached{}}
}

// Titles returns the merged catalog. Callers must not modify it.
func (s *Store) Titles() []Title {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.titles
}

func (s *Store) Statuses() []Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Status(nil), s.statuses...)
}

// Refresh fetches every source in parallel and rebuilds the catalog.
func (s *Store) Refresh(ctx context.Context) {
	type fetched struct {
		titles []Title
		err    error
		at     time.Time
	}
	res := make([]fetched, len(s.sources))
	var wg sync.WaitGroup
	for i, src := range s.sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fctx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			t, err := src.Fetch(fctx)
			res[i] = fetched{t, err, time.Now()}
		}()
	}
	wg.Wait()

	results := make([]SourceResult, 0, len(s.sources))
	statuses := make([]Status, 0, len(s.sources))
	for i, src := range s.sources {
		r, st := res[i], Status{Name: src.Name()}
		if r.err == nil {
			s.saveCache(src.Name(), cached{r.at, r.titles})
			st.FetchedAt, st.Titles = r.at, len(r.titles)
			results = append(results, SourceResult{src.Name(), src.Priority(), r.titles})
		} else {
			st.Error = r.err.Error()
			s.log.Warn("source fetch failed", "source", src.Name(), "err", r.err)
			if c, ok := s.loadCache(src.Name()); ok {
				st.FromCache, st.FetchedAt, st.Titles = true, c.FetchedAt, len(c.Titles)
				results = append(results, SourceResult{src.Name(), src.Priority(), c.Titles})
			}
		}
		statuses = append(statuses, st)
	}

	merged := Merge(results)
	s.mu.Lock()
	s.titles, s.statuses = merged, statuses
	s.mu.Unlock()
	s.log.Info("catalog refreshed", "titles", len(merged), "sources", len(s.sources))
}

// Run refreshes now and then every interval until ctx ends.
func (s *Store) Run(ctx context.Context, interval time.Duration) {
	s.Refresh(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Refresh(ctx)
		}
	}
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (s *Store) cachePath(name string) string {
	return filepath.Join(s.cacheDir, "source-"+unsafeChars.ReplaceAllString(name, "_")+".json")
}

func (s *Store) saveCache(name string, c cached) {
	s.mu.Lock()
	s.lastGood[name] = c
	s.mu.Unlock()
	if s.cacheDir == "" {
		return
	}
	err := func() error {
		if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
			return err
		}
		data, err := json.Marshal(c)
		if err != nil {
			return err
		}
		tmp := s.cachePath(name) + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, s.cachePath(name))
	}()
	if err != nil {
		s.log.Warn("writing source cache", "source", name, "err", err)
	}
}

func (s *Store) loadCache(name string) (cached, bool) {
	s.mu.RLock()
	c, ok := s.lastGood[name]
	s.mu.RUnlock()
	if ok || s.cacheDir == "" {
		return c, ok
	}
	data, err := os.ReadFile(s.cachePath(name))
	if err != nil {
		return cached{}, false
	}
	if err := json.Unmarshal(data, &c); err != nil {
		s.log.Warn("bad source cache", "source", name, "err", fmt.Errorf("%s: %w", s.cachePath(name), err))
		return cached{}, false
	}
	return c, true
}
