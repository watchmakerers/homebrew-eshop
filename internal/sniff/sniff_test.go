package sniff

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func newRec(t *testing.T) *Recorder {
	rec, err := NewRecorder(t.TempDir(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rec.Close() })
	return rec
}

func startDNS(t *testing.T, h dns.Handler) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	s := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: func() { close(started) }}
	go s.ActivateAndServe()
	<-started
	t.Cleanup(func() { s.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNS(t *testing.T) {
	// Fake upstream: answers everything with 9.9.9.9.
	upstream := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(9, 9, 9, 9)})
		w.WriteMsg(m)
	}))
	rec := newRec(t)
	addr := startDNS(t, &DNS{Upstream: upstream, AnswerIP: netip.MustParseAddr("192.168.1.50"), Patterns: DefaultPatterns, Rec: rec})

	ask := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		resp, err := dns.Exchange(m, addr)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for name, want := range map[string]string{
		"samurai.ctr.shop.pretendo.cc": "192.168.1.50",
		"NUS.C.Shop.NintendoWifi.net":  "192.168.1.50",
		"nasc.pretendo.cc":             "9.9.9.9",
		"conntest.nintendowifi.net":    "9.9.9.9",
		"shop.nintendo.net.evil.com":   "9.9.9.9",
	} {
		resp := ask(name, dns.TypeA)
		if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != want {
			t.Errorf("%s: %v, want %s", name, resp.Answer, want)
		}
	}
	if resp := ask("ninja.ctr.shop.nintendo.net", dns.TypeAAAA); len(resp.Answer) != 0 || resp.Rcode != dns.RcodeSuccess {
		t.Errorf("AAAA for intercepted host: %v", resp)
	}

	data, _ := os.ReadFile(filepath.Join(rec.Dir, "events.jsonl"))
	if !strings.Contains(string(data), `"name":"nasc.pretendo.cc"`) {
		t.Errorf("forwarded query not recorded:\n%s", data)
	}
}

func TestHandlerCannedResponseAndTraversal(t *testing.T) {
	rec := newRec(t)
	resp := t.TempDir()
	os.MkdirAll(filepath.Join(resp, "ninja.ctr.shop.pretendo.cc", "ninja", "ws"), 0o755)
	os.WriteFile(filepath.Join(resp, "ninja.ctr.shop.pretendo.cc", "ninja", "ws", "country.xml"), []byte("<x/>"), 0o644)
	os.WriteFile(filepath.Join(filepath.Dir(resp), "secret"), []byte("nope"), 0o644)

	srv := httptest.NewServer(&Handler{Rec: rec, Responses: resp, Listener: "http"})
	defer srv.Close()

	get := func(host, path string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader("hello"))
		req.Host = host
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if code, body := get("ninja.ctr.shop.pretendo.cc:443", "/ninja/ws/country.xml?x=1"); code != 200 || body != "<x/>" {
		t.Errorf("canned: %d %q", code, body)
	}
	os.WriteFile(filepath.Join(resp, "ninja.ctr.shop.pretendo.cc", "ninja", "ws", "country.xml.status"), []byte("201\n"), 0o644)
	if code, body := get("ninja.ctr.shop.pretendo.cc", "/ninja/ws/country.xml"); code != 201 || body != "<x/>" {
		t.Errorf("status sidecar: %d %q", code, body)
	}
	os.Remove(filepath.Join(resp, "ninja.ctr.shop.pretendo.cc", "ninja", "ws", "country.xml.status"))
	if code, _ := get("ninja.ctr.shop.pretendo.cc", "/../../secret"); code != 404 {
		t.Errorf("path traversal served: %d", code)
	}
	if code, _ := get("..", "/secret"); code != 404 {
		t.Errorf("host traversal served: %d", code)
	}

	f, _ := os.Open(filepath.Join(rec.Dir, "events.jsonl"))
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	if line := sc.Text(); !strings.Contains(line, `"body_len":5`) || !strings.Contains(line, `"status":200`) {
		t.Errorf("event: %s", line)
	}
	bodies, _ := os.ReadDir(filepath.Join(rec.Dir, "bodies"))
	if len(bodies) != 4 {
		t.Errorf("%d bodies saved, want 4", len(bodies))
	}
}

// The 3DS speaks TLS 1.0 with RSA key exchange; Go must still accept that with our config.
func TestLegacyTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	cert, err := LoadOrCreateCert(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCert(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")); err != nil {
		t.Fatalf("reload: %v", err)
	}
	rec := newRec(t)
	srv := httptest.NewUnstartedServer(&Handler{Rec: rec, Listener: "https"})
	srv.TLS = LegacyTLSConfig(cert, rec)
	srv.StartTLS()
	defer srv.Close()

	for _, suite := range []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA} {
		conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, ServerName: "ccif.ctr.shop.pretendo.cc",
			MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{suite},
		})
		if err != nil {
			t.Fatalf("%s: %v", tls.CipherSuiteName(suite), err)
		}
		conn.Close()
	}
	data, _ := os.ReadFile(filepath.Join(rec.Dir, "events.jsonl"))
	if !strings.Contains(string(data), `"sni":"ccif.ctr.shop.pretendo.cc"`) {
		t.Errorf("hello not recorded:\n%s", data)
	}
}
