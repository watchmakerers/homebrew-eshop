// bgm-pack makes the 3DS eShop's seasonal background music files from ordinary audio files.
//
// The eShop has two music slots. Each is a pair of plain files in its extdata, which it used to get over
// SpotPass (BOSS tasks BGM1/BGM2):
//
//	boss_xml<N>   a short XML header: when the track plays, its size and loop points
//	boss_bgm<N>   the audio, raw AAC (ADTS)
//
// When the shop opens it plays a slot whose window contains the console's date, else its built-in music.
// The header fields come from the eShop app's parser (TIGER, 0x284530): every value is decimal; version must be 1;
// a window is begin <= now <= end unless indefinite is 1; loopStartFrame/loopEndFrame are sample frames, and a
// loop shorter than 32000 frames is ignored.
//
// Usage:
//
//	go run ./cmd/bgm-pack [-calendar bgm/calendar.yaml] [-date 2026-12-01] [-out bgm/out]
//
// picks the calendar entry playing on -date for slot 1 and the next one for slot 2, each with its window in that
// year, and writes both pairs (plus a .payload of each, the form a SpotPass server would wrap) to -out.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Calendar lists the seasons. A season starts on its month/day and runs until the next one starts, wrapping
// around the year.
type Calendar struct {
	Bitrate string   `yaml:"bitrate"` // ffmpeg AAC bitrate, default 64k
	Seasons []Season `yaml:"seasons"`
}

type Season struct {
	Name  string `yaml:"name"`
	Start string `yaml:"start"` // MM-DD
	File  string `yaml:"file"`  // relative to the calendar file
}

func main() {
	calPath := flag.String("calendar", "bgm/calendar.yaml", "season calendar")
	dateStr := flag.String("date", time.Now().Format("2006-01-02"), "the date to pack for (slot 1 = the season playing then)")
	out := flag.String("out", "bgm/out", "output folder")
	flag.Parse()

	data, err := os.ReadFile(*calPath)
	check(err)
	var cal Calendar
	check(yaml.Unmarshal(data, &cal))
	if len(cal.Seasons) == 0 {
		fail("calendar has no seasons")
	}
	if cal.Bitrate == "" {
		cal.Bitrate = "64k"
	}
	date, err := time.ParseInLocation("2006-01-02", *dateStr, time.Local)
	check(err)

	windows, err := seasonWindows(cal.Seasons, date)
	check(err)
	check(os.MkdirAll(*out, 0o755))
	for slot, w := range windows {
		n := slot + 1
		src := w.season.File
		if !filepath.IsAbs(src) {
			src = filepath.Join(filepath.Dir(*calPath), src)
		}
		aac, err := encode(src, cal.Bitrate)
		check(err)
		frames, err := sampleFrames(aac)
		check(err)
		xml := header(n, w.begin, w.end, len(aac), frames)
		check(os.WriteFile(filepath.Join(*out, fmt.Sprintf("boss_bgm%d", n)), aac, 0o644))
		check(os.WriteFile(filepath.Join(*out, fmt.Sprintf("boss_xml%d", n)), xml, 0o644))
		check(os.WriteFile(filepath.Join(*out, fmt.Sprintf("BGM%d.payload", n)), payload(xml, aac), 0o644))
		fmt.Printf("slot %d: %-28s %s -> %s  (%d KB, %.0fs)\n", n, w.season.Name,
			w.begin.Format("2006-01-02"), w.end.Format("2006-01-02 15:04:05"), len(aac)/1024, float64(frames)/44100)
	}
	fmt.Printf("\nCopy boss_bgm1, boss_xml1, boss_bgm2 and boss_xml2 from %s into the eShop's extdata.\n", *out)
}

type window struct {
	season     Season
	begin, end time.Time
}

// seasonWindows returns the season playing on date and the one after it, each with its exact window.
func seasonWindows(seasons []Season, date time.Time) ([]window, error) {
	type start struct {
		s     Season
		month time.Month
		day   int
	}
	var starts []start
	for _, s := range seasons {
		t, err := time.Parse("01-02", s.Start)
		if err != nil {
			return nil, fmt.Errorf("season %q: start %q isn't MM-DD", s.Name, s.Start)
		}
		starts = append(starts, start{s, t.Month(), t.Day()})
	}
	sort.Slice(starts, func(i, j int) bool {
		return starts[i].month < starts[j].month || starts[i].month == starts[j].month && starts[i].day < starts[j].day
	})
	at := func(i, year int) time.Time {
		st := starts[i%len(starts)]
		return time.Date(year, st.month, st.day, 0, 0, 0, 0, time.Local)
	}
	// The current season is the last start on or before date (possibly last year's final one).
	cur, year := len(starts)-1, date.Year()-1
	for i := range starts {
		if !at(i, date.Year()).After(date) {
			cur, year = i, date.Year()
		}
	}
	var out []window
	for k := 0; k < 2 && k < len(starts); k++ {
		i := cur + k
		y := year + i/len(starts)
		begin := at(i, y)
		ny := year + (i+1)/len(starts)
		end := at(i+1, ny).Add(-time.Second)
		out = append(out, window{starts[i%len(starts)].s, begin, end})
	}
	return out, nil
}

// encode converts any audio file to 44.1 kHz stereo AAC-LC in ADTS frames.
func encode(src, bitrate string) ([]byte, error) {
	cmd := exec.Command("ffmpeg", "-v", "error", "-i", src, "-vn", "-map_metadata", "-1",
		"-ac", "2", "-ar", "44100", "-c:a", "aac", "-profile:a", "aac_low", "-b:a", bitrate, "-f", "adts", "-")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg %s: %v: %s", src, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// sampleFrames counts ADTS frames (1024 samples each).
func sampleFrames(adts []byte) (int, error) {
	n := 0
	for off := 0; off+7 <= len(adts); n++ {
		if adts[off] != 0xFF || adts[off+1]&0xF0 != 0xF0 {
			return 0, fmt.Errorf("bad ADTS sync at %d", off)
		}
		l := int(adts[off+3]&3)<<11 | int(adts[off+4])<<3 | int(adts[off+5])>>5
		if l < 7 {
			return 0, fmt.Errorf("bad ADTS frame length at %d", off)
		}
		off += l
	}
	return n * 1024, nil
}

// header is the boss_xml file. The downloader only accepted 0xF0-0x400 bytes, so it's padded to at least 0xF0.
func header(task int, begin, end time.Time, dataSize, frames int) []byte {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<bgm>\n")
	field := func(k string, v int) { fmt.Fprintf(&b, "  <%s>%d</%s>\n", k, v, k) }
	field("version", 1)
	field("task", task)
	field("priority", 1)
	for _, p := range []struct {
		pre string
		t   time.Time
	}{{"begin", begin}, {"end", end}} {
		field(p.pre+"Year", p.t.Year())
		field(p.pre+"Month", int(p.t.Month()))
		field(p.pre+"Day", p.t.Day())
		field(p.pre+"Hour", p.t.Hour())
		field(p.pre+"Minute", p.t.Minute())
		field(p.pre+"Second", p.t.Second())
	}
	field("indefinite", 0)
	field("dataSize", dataSize)
	field("loopStartFrame", 0)
	field("loopEndFrame", frames)
	b.WriteString("</bgm>\n")
	s := b.String()
	for len(s) < 0xF0 {
		s += " "
	}
	return []byte(s)
}

// payload is what was inside the BOSS container: the header's length (u32 LE), the header, the audio.
func payload(xml, aac []byte) []byte {
	out := make([]byte, 4, 4+len(xml)+len(aac))
	binary.LittleEndian.PutUint32(out, uint32(len(xml)))
	return append(append(out, xml...), aac...)
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "bgm-pack:", msg)
	os.Exit(1)
}
