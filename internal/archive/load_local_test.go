package archive

import (
	"os"
	"testing"
)

// Runs against a real archive when ESHOP_ARCHIVE points at one.
func TestLoadReal(t *testing.T) {
	root := os.Getenv("ESHOP_ARCHIVE")
	if root == "" {
		t.Skip("ESHOP_ARCHIVE not set")
	}
	x, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	icons, banners, desc := 0, 0, 0
	for _, ti := range x.Titles {
		if ti.Icon != "" {
			icons++
		}
		if ti.Banner != "" {
			banners++
		}
		if ti.Description != "" {
			desc++
		}
	}
	t.Logf("%d titles (%d icons, %d banners, %d descriptions), %d dirs", len(x.Titles), icons, banners, desc, len(x.Dirs))
	for _, d := range x.Dirs {
		t.Logf("dir %d %q %s icon=%v banner=%v", d.ID, d.Name, d.Country, d.Icon != "", d.Banner != "")
	}
	if len(x.Titles) > 0 {
		t.Logf("newest: %+v", *x.Titles[0])
	}
}
