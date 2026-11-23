package sniff

import (
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"homebrew-eshop/internal/bgm"
)

// BGM answers the eShop's SpotPass music task with the season playing now. The app registers BOSS tasks that
// fetch https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/<task>/BGM<N>/<REGION>_BGM<N>
// (one task ID per region; US CtfKXACbUPl8s7lk). Slot 1 gets the current season and slot 2 the next, each with
// its own play window, so the app switches tracks on its own when the date passes.
type BGM struct {
	Calendar *bgm.Calendar
	Key      []byte // the BOSS AES key from the user's console

	mu    sync.Mutex
	cache map[string][]byte
}

// BGMHost is the Akamai host the eShop's music task downloads from; intercept it only when serving music.
const BGMHost = "a248.e.akamai.net"

var bgmPath = regexp.MustCompile(`/p01/nsa/[A-Za-z0-9]+/BGM([12])/([A-Z]{2})_BGM[12]$`)

func (b *BGM) respond(path string) *stubReply {
	m := bgmPath.FindStringSubmatch(path)
	if m == nil {
		return nil
	}
	slot, _ := strconv.Atoi(m[1])
	region := m[2]
	windows, err := bgm.Windows(b.Calendar.Seasons, time.Now())
	if err != nil || slot > len(windows) {
		return nil
	}
	w := windows[slot-1]
	key := fmt.Sprintf("%s-%d-%s-%s", region, slot, w.Season.Name, w.Begin.Format("20060102"))
	b.mu.Lock()
	defer b.mu.Unlock()
	data := b.cache[key]
	if data == nil {
		t, err := b.Calendar.Make(slot, w)
		if err != nil {
			return nil
		}
		data, err = bgm.SpotPassFile(b.Key, region, slot, w, bgm.Payload(t.XML, t.Audio))
		if err != nil {
			return nil
		}
		if b.cache == nil {
			b.cache = map[string][]byte{}
		}
		b.cache[key] = data
	}
	return &stubReply{name: fmt.Sprintf("spotpass %s BGM%d: %s (%s to %s)", region, slot, w.Season.Name,
		w.Begin.Format("2006-01-02"), w.End.Format("2006-01-02")), contentType: "application/octet-stream", body: data}
}
