package catalog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

func TestMerge(t *testing.T) {
	low := SourceResult{Name: "low", Priority: 1, Titles: []Title{
		{Name: "Shared", TitleID: 0x0004000000ABC00, Description: "from low", CIA: &CIASource{URL: "low.cia"}},
		{Name: "Only Low"},
		{Name: "Same-Name App", Author: "low author"},
	}}
	high := SourceResult{Name: "high", Priority: 9, Titles: []Title{
		{Name: "Shared (better name)", TitleID: 0x0004000000ABC00, Version: "v2"},
		{Name: "same name app"},
	}}
	got := Merge([]SourceResult{low, high})
	if len(got) != 3 {
		t.Fatalf("got %d titles: %+v", len(got), got)
	}
	byName := map[string]Title{}
	for _, x := range got {
		byName[x.Name] = x
	}
	s := byName["Shared (better name)"]
	if s.Source != "high" || s.Version != "v2" || s.Description != "from low" || s.CIA == nil || s.CIA.URL != "low.cia" {
		t.Errorf("shared: %+v", s)
	}
	if len(s.AlsoIn) != 1 || s.AlsoIn[0] != "low" {
		t.Errorf("also_in: %v", s.AlsoIn)
	}
	if a := byName["same name app"]; a.Source != "high" || a.Author != "low author" {
		t.Errorf("name match: %+v", a)
	}
}

type fakeSource struct {
	name   string
	titles []Title
	err    error
}

func (f *fakeSource) Name() string                           { return f.name }
func (f *fakeSource) Priority() int                          { return 0 }
func (f *fakeSource) Fetch(context.Context) ([]Title, error) { return f.titles, f.err }

func TestStoreFallsBackToCache(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	src := &fakeSource{name: "flaky/store", titles: []Title{{Name: "A"}}}

	NewStore([]Source{src}, dir, log).Refresh(context.Background())

	// A new store (as after a restart) whose source is down should still serve the cached titles.
	src.titles, src.err = nil, errors.New("down")
	s := NewStore([]Source{src}, dir, log)
	s.Refresh(context.Background())
	if len(s.Titles()) != 1 || s.Titles()[0].Name != "A" {
		t.Fatalf("titles: %+v", s.Titles())
	}
	if st := s.Statuses()[0]; !st.FromCache || st.Error != "down" {
		t.Fatalf("status: %+v", st)
	}
}
