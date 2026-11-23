package sniff

import (
	"bytes"
	"encoding/binary"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"homebrew-eshop/internal/bgm"
	"homebrew-eshop/internal/boss"
)

func TestSpotPassBGM(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
	dir := t.TempDir()
	tone := filepath.Join(dir, "tone.wav")
	if out, err := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "sine=frequency=440:duration=2", tone).CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg: %v %s", err, out)
	}
	cal := filepath.Join(dir, "calendar.yaml")
	os.WriteFile(cal, []byte("seasons:\n  - {name: A, start: \"01-01\", file: tone.wav}\n  - {name: B, start: \"07-01\", file: tone.wav}\n"), 0o644)
	c, err := bgm.LoadCalendar(cal)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 16) // stand-in
	st := &Stubs{BGM: &BGM{Calendar: c, Key: key}}
	path := "/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/CtfKXACbUPl8s7lk/BGM2/US_BGM2"
	r := st.Respond(BGMHost, httptest.NewRequest("GET", "https://"+BGMHost+path, nil), nil)
	if r == nil {
		t.Fatal("no reply")
	}
	f, err := boss.Open(key, r.body)
	if err != nil {
		t.Fatal(err)
	}
	if f.Payload.ProgramID != 0x0004001000021900 {
		t.Errorf("program %016X", f.Payload.ProgramID)
	}
	p := f.Payload.Data
	n := binary.LittleEndian.Uint32(p)
	xml := p[4 : 4+n]
	if n < 0xF0 || n > 0x400 || !bytes.Contains(xml, []byte("<task>2</task>")) || !bytes.Contains(xml, []byte("<version>1</version>")) {
		t.Errorf("header (%d bytes): %s", n, xml)
	}
	if audio := p[4+n:]; len(audio) < 7 || audio[0] != 0xFF || audio[1]&0xF0 != 0xF0 {
		t.Error("payload audio isn't ADTS")
	}
	if st.Respond(BGMHost, httptest.NewRequest("GET", "https://"+BGMHost+"/something/else", nil), nil) != nil {
		t.Error("answered a non-BGM path")
	}
}
