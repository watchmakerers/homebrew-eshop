// bgm-pack makes the 3DS eShop's seasonal background music files from ordinary audio files (see package bgm).
//
//	go run ./cmd/bgm-pack [-calendar bgm/calendar.yaml] [-date 2026-12-01] [-out bgm/out] [-boss-key key.txt -region JP]
//
// It picks the calendar entry playing on -date for slot 1 and the next one for slot 2, each with its window in
// that year, and writes boss_xml<N> + boss_bgm<N> (to copy into the eShop's extdata by hand) and BGM<N>.payload.
// With -boss-key (the BOSS AES key from your own console) it also writes BGM<N>.boss, the encrypted SpotPass file.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"homebrew-eshop/internal/bgm"
	"homebrew-eshop/internal/boss"
)

func main() {
	calPath := flag.String("calendar", "bgm/calendar.yaml", "season calendar")
	dateStr := flag.String("date", time.Now().Format("2006-01-02"), "the date to pack for (slot 1 = the season playing then)")
	out := flag.String("out", "bgm/out", "output folder")
	keyFile := flag.String("boss-key", "", "file with the BOSS AES key (32 hex digits); also write encrypted BGM<N>.boss")
	region := flag.String("region", "JP", "eShop region the .boss files are for: JP, US, EU, KR or TW")
	flag.Parse()

	cal, err := bgm.LoadCalendar(*calPath)
	check(err)
	date, err := time.ParseInLocation("2006-01-02", *dateStr, time.Local)
	check(err)
	var key []byte
	if *keyFile != "" {
		key, err = boss.LoadKey(*keyFile)
		check(err)
	}
	windows, err := bgm.Windows(cal.Seasons, date)
	check(err)
	check(os.MkdirAll(*out, 0o755))
	for i, w := range windows {
		n := i + 1
		t, err := cal.Make(n, w)
		check(err)
		write := func(name string, b []byte) { check(os.WriteFile(filepath.Join(*out, name), b, 0o644)) }
		write(fmt.Sprintf("boss_bgm%d", n), t.Audio)
		write(fmt.Sprintf("boss_xml%d", n), t.XML)
		payload := bgm.Payload(t.XML, t.Audio)
		write(fmt.Sprintf("BGM%d.payload", n), payload)
		if key != nil {
			f, err := bgm.SpotPassFile(key, *region, n, w, payload)
			check(err)
			write(fmt.Sprintf("BGM%d.boss", n), f)
		}
		fmt.Printf("slot %d: %-28s %s -> %s  (%d KB, %.0fs)\n", n, w.Season.Name,
			w.Begin.Format("2006-01-02"), w.End.Format("2006-01-02 15:04:05"), len(t.Audio)/1024, float64(t.Frames)/bgm.Rate)
	}
	fmt.Printf("\nCopy boss_bgm1, boss_xml1, boss_bgm2 and boss_xml2 from %s into the eShop's extdata.\n", *out)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "bgm-pack:", err)
		os.Exit(1)
	}
}
