package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RefreshInterval != 6*time.Hour || len(cfg.Sources) != 1 || cfg.Sources[0].Type != "unistore" {
		t.Fatalf("%+v", cfg)
	}
}

func TestValidation(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{"sources: [{name: a, type: ftp}]", "unknown type"},
		{"sources: [{name: a, type: unistore}]", "needs url"},
		{"sources: [{name: a, type: github, repo: nope}]", "owner/name"},
		{"sources: [{name: a, type: github, repo: o/r, title_id: '123'}]", "16 hex digits"},
		{"sources: [{name: a, type: local, path: x}, {name: a, type: local, path: y}]", "duplicate"},
		{"sources: [{name: a, type: local, pth: x}]", "not found"}, // typo'd field
	} {
		if _, err := Parse([]byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want error containing %q", tc.yaml, err, tc.want)
		}
	}
}
