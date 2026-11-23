// Package catalog holds the shared title model, merges what the sources return, and caches it.
package catalog

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

// Title is one app in the store, in the form every source adapter converts to.
type Title struct {
	Name        string   `json:"name"`
	Author      string   `json:"author,omitempty"`
	Description string   `json:"description,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	Version     string   `json:"version,omitempty"`
	License     string   `json:"license,omitempty"`
	Updated     string   `json:"updated,omitempty"`
	Size        string   `json:"size,omitempty"`
	TitleID     uint64   `json:"title_id,omitempty"` // 0 when unknown
	// ProductCode is from the CIA's NCCH header ("CTR-P-AJRE"); empty when unknown or encrypted.
	ProductCode string       `json:"product_code,omitempty"`
	IconURL     string       `json:"icon_url,omitempty"`
	BannerURL   string       `json:"banner_url,omitempty"`
	Screenshots []Screenshot `json:"screenshots,omitempty"`
	// CIA is where the installable package comes from. nil means the app can't be installed through the
	// eShop (e.g. it's only a .3dsx); it still shows up in the catalog for other uses.
	CIA *CIASource `json:"cia,omitempty"`
	// Backup marks the user's own dump of a game they own, from a "backups" source on this machine.
	Backup bool `json:"backup,omitempty"`

	// Filled in by Merge.
	Source string   `json:"source,omitempty"`  // the source whose entry won
	AlsoIn []string `json:"also_in,omitempty"` // other sources listing the same app
}

type Screenshot struct {
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

// CIASource says how to obtain a title's .cia. Exactly one of URL, Repo or Path is set.
type CIASource struct {
	URL   string `json:"url,omitempty"`   // direct download
	Repo  string `json:"repo,omitempty"`  // GitHub owner/name: an asset of the latest release
	Asset string `json:"asset,omitempty"` // asset name or glob, with Repo
	Path  string `json:"path,omitempty"`  // file on this server
	// Member is a regexp naming the .cia inside the downloaded archive; empty when the download is the .cia itself.
	Member string `json:"member,omitempty"`
}

// HomebrewTitleID turns a homebrew unique ID (what UniStores list in title_ids) into a full 3DS title ID:
// application high ID 00040000, unique ID in bits 8-27, variation 00.
func HomebrewTitleID(uniqueID uint32) uint64 {
	return 0x0004000000000000 | uint64(uniqueID&0xFFFFF)<<8
}

// Key identifies a title across sources: its title ID when known, else its normalised name.
func (t *Title) Key() string {
	if t.TitleID != 0 {
		return fmt.Sprintf("%016X", t.TitleID)
	}
	var b strings.Builder
	for _, r := range strings.ToLower(t.Name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return "name:" + b.String()
}

// Source is a catalog source adapter (see package sources).
type Source interface {
	Name() string
	Priority() int
	Fetch(ctx context.Context) ([]Title, error)
}
