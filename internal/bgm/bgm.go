// Package bgm makes the 3DS eShop's seasonal background music: the boss_xml header (when a track plays, its size
// and loop points) and boss_bgm audio (raw ADTS AAC), from a season calendar and ordinary audio files.
//
// The header fields come from the eShop app's parser (TIGER 0x284530): every value is decimal; version must be 1;
// a track plays when begin <= now <= end (or indefinite is 1); loopStartFrame/loopEndFrame are sample frames, and
// a loop shorter than 32000 frames is ignored. Over SpotPass the app takes a payload of u32 LE header length,
// header, audio (downloader 0x169dd0).
package bgm

import (
	"bytes"
	"encoding/binary"
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
	Bitrate string   `yaml:"bitrate"` // ffmpeg AAC bitrate; default: as high as fits in MaxSize (at most 96k)
	Seasons []Season `yaml:"seasons"`
}

type Season struct {
	Name  string `yaml:"name"`
	Start string `yaml:"start"` // MM-DD
	File  string `yaml:"file"`  // relative to the calendar file
	// Loop is [start, end] in seconds of the source: the eShop plays to end, then jumps back to start. The audio
	// is cut a second after end. Without it the whole file plays and loops from the beginning.
	Loop []float64 `yaml:"loop"`
}

// LoadCalendar reads a calendar file. Relative season files are resolved against its folder.
func LoadCalendar(path string) (*Calendar, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cal Calendar
	if err := yaml.Unmarshal(data, &cal); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cal.Seasons) == 0 {
		return nil, fmt.Errorf("%s: no seasons", path)
	}
	for i := range cal.Seasons {
		if l := cal.Seasons[i].Loop; l != nil && (len(l) != 2 || l[0] < 0 || l[1] <= l[0]) {
			return nil, fmt.Errorf("%s: season %q: loop must be [start, end] seconds", path, cal.Seasons[i].Name)
		}
		if f := cal.Seasons[i].File; !filepath.IsAbs(f) {
			cal.Seasons[i].File = filepath.Join(filepath.Dir(path), f)
		}
	}
	return &cal, nil
}

// Track is one slot's files.
type Track struct {
	Window Window
	XML    []byte // boss_xml<N>
	Audio  []byte // boss_bgm<N>
	Frames int
}

// Make encodes the season's audio and writes its header for slot n (1 or 2).
func (c *Calendar) Make(n int, w Window) (*Track, error) {
	var cut float64 // seconds of source to keep; 0 = all
	if l := w.Season.Loop; l != nil {
		cut = l[1] + 1
	}
	aac, err := Encode(w.Season.File, c.Bitrate, cut)
	if err != nil {
		return nil, err
	}
	if len(aac) > MaxSize {
		return nil, fmt.Errorf("%s: %d bytes encoded, more than the %d the eShop's own files use; shorten the loop or lower the bitrate",
			w.Season.File, len(aac), MaxSize)
	}
	frames, err := SampleFrames(aac)
	if err != nil {
		return nil, err
	}
	loopStart, loopEnd := 0, frames
	if l := w.Season.Loop; l != nil {
		loopStart, loopEnd = Delay+int(l[0]*Rate+0.5), Delay+int(l[1]*Rate+0.5)
	}
	return &Track{Window: w, XML: Header(n, w.Begin, w.End, len(aac), loopStart, loopEnd), Audio: aac, Frames: frames}, nil
}

// Window is when a season plays, in one particular year.
type Window struct {
	Season     Season
	Begin, End time.Time
}

// Windows returns the season playing on date and the one after it, each with its exact window.
func Windows(seasons []Season, date time.Time) ([]Window, error) {
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
	var out []Window
	for k := 0; k < 2 && k < len(starts); k++ {
		i := cur + k
		y := year + i/len(starts)
		begin := at(i, y)
		ny := year + (i+1)/len(starts)
		end := at(i+1, ny).Add(-time.Second)
		out = append(out, Window{starts[i%len(starts)].s, begin, end})
	}
	return out, nil
}

// The format of Nintendo's own boss_bgm files (the last one Nintendo sent is still in many consoles' extdata):
// 32 kHz stereo AAC-LC in MPEG-2 ADTS frames, 96 kbit/s, exactly 921600 bytes.
const (
	Rate    = 32000
	MaxSize = 921600
	Delay   = 1024 // ffmpeg's AAC encoder puts one frame of priming samples in front, which the eShop plays
)

// Encode converts any audio file (its first cut seconds, or all of it when cut is 0) to Nintendo's format. With
// no bitrate given it picks the highest that fits in MaxSize, up to Nintendo's 96k.
func Encode(src, bitrate string, cut float64) ([]byte, error) {
	if bitrate != "" {
		return encode(src, bitrate, cut)
	}
	secs := cut
	if secs == 0 {
		out, err := exec.Command("ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", src).Output()
		if err != nil {
			return nil, fmt.Errorf("ffprobe %s: %v", src, err)
		}
		if _, err := fmt.Sscan(string(out), &secs); err != nil {
			return nil, fmt.Errorf("ffprobe %s: duration %q", src, out)
		}
	}
	kbps := min(96, int(float64(MaxSize)*8/secs/1000))
	for ; kbps >= 24; kbps -= 4 {
		aac, err := encode(src, fmt.Sprintf("%dk", kbps), cut)
		if err != nil || len(aac) <= MaxSize {
			return aac, err
		}
	}
	return nil, fmt.Errorf("%s: %.0f seconds doesn't fit in %d bytes even at 24k", src, secs, MaxSize)
}

func encode(src, bitrate string, cut float64) ([]byte, error) {
	args := []string{"-v", "error", "-i", src}
	if cut > 0 {
		args = append(args, "-t", fmt.Sprint(cut))
	}
	args = append(args, "-vn", "-map_metadata", "-1", "-ac", "2", "-ar", fmt.Sprint(Rate),
		"-c:a", "aac", "-profile:a", "aac_low", "-b:a", bitrate, "-f", "adts", "-")
	cmd := exec.Command("ffmpeg", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg %s: %v: %s", src, err, stderr.String())
	}
	aac := stdout.Bytes()
	// Mark the frames MPEG-2 like Nintendo's (the same AAC-LC either way).
	for off := 0; off+7 <= len(aac); {
		aac[off+1] |= 0x08
		l := int(aac[off+3]&3)<<11 | int(aac[off+4])<<3 | int(aac[off+5])>>5
		if l < 7 {
			break
		}
		off += l
	}
	return aac, nil
}

// SampleFrames counts ADTS frames (1024 samples each).
func SampleFrames(adts []byte) (int, error) {
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

// Header is the boss_xml file, laid out like Nintendo's: one line under the declaration, root <header>. The
// downloader only accepted 0xF0-0x400 bytes, so it's padded to at least 0xF0.
func Header(task int, begin, end time.Time, dataSize, loopStart, loopEnd int) []byte {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<header>")
	field := func(k string, v int) { fmt.Fprintf(&b, "<%s>%d</%s>", k, v, k) }
	field("version", 1)
	field("task", task)
	field("priority", 16)
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
	field("loopStartFrame", loopStart)
	field("loopEndFrame", loopEnd)
	b.WriteString("</header>\n")
	s := b.String()
	for len(s) < 0xF0 {
		s += " "
	}
	return []byte(s)
}

// Payload is what was inside the BOSS container: the header's length (u32 LE), the header, the audio.
func Payload(xml, aac []byte) []byte {
	out := make([]byte, 4, 4+len(xml)+len(aac))
	binary.LittleEndian.PutUint32(out, uint32(len(xml)))
	return append(append(out, xml...), aac...)
}
