package sniff

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const refusal = `<?xml version="1.0"?><errors><error><code>1021</code><message>The requested game server was not found</message></error></errors>`

func TestAccountProxy(t *testing.T) {
	// Fake Pretendo: refuses every service token with 1021 (status 200, like the real one), echoes everything else.
	var gotAuth, gotBody string
	pretendo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == serviceTokenPath {
			w.Write([]byte(refusal))
			return
		}
		b, _ := io.ReadAll(r.Body)
		gotAuth, gotBody = r.Header.Get("Authorization"), string(b)
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("<ok/>"))
	}))
	defer pretendo.Close()

	rec := newRec(t)
	proxy := &AccountProxy{Upstream: pretendo.URL, Client: pretendo.Client(), Rec: rec}
	front := httptest.NewUnstartedServer(&Handler{Rec: rec, Account: proxy, Listener: "https"})
	front.StartTLS()
	defer front.Close()

	do := func(method, path, titleID, body string) (int, string, http.Header) {
		req, _ := http.NewRequest(method, front.URL+path, strings.NewReader(body))
		req.Host = AccountHost
		req.Header.Set("Authorization", "Bearer SECRET-ACCESS-TOKEN")
		if titleID != "" {
			req.Header.Set("X-Nintendo-Title-Id", titleID)
		}
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}

	// Ordinary traffic passes through untouched, both ways.
	code, body, hdr := do("POST", "/v1/api/oauth20/access_token/generate", "", "password=SECRET-PASSWORD-HASH")
	if code != http.StatusCreated || body != "<ok/>" || hdr.Get("X-Upstream") != "yes" {
		t.Errorf("passthrough: %d %q %v", code, body, hdr)
	}
	if gotAuth != "Bearer SECRET-ACCESS-TOKEN" || gotBody != "password=SECRET-PASSWORD-HASH" {
		t.Errorf("upstream got auth %q body %q", gotAuth, gotBody)
	}

	// The eShop's token is answered here without asking Pretendo.
	pretendoCalls := 0
	inner := pretendo.Config.Handler
	pretendo.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { pretendoCalls++; inner.ServeHTTP(w, r) })
	_, body, _ = do("GET", serviceTokenPath+"?client_id=71a6f5d6430ea0183e3917787d717c46", "0004001000020900", "")
	if !strings.HasPrefix(body, `<?xml version="1.0"?><service_token><token>`) || pretendoCalls != 0 {
		t.Errorf("eShop token: %s (Pretendo called %d times)", body, pretendoCalls)
	}
	// The eShop's push notification token too (NPNSHost is ours while the proxy runs).
	if _, body, _ = do("GET", serviceTokenPath+"?client_id=24755a2fe31f4d32ab9aa24ce5a2bdac", "0004001000020900", ""); !strings.Contains(body, "<service_token>") || pretendoCalls != 0 {
		t.Errorf("NPNS token: %s (Pretendo called %d times)", body, pretendoCalls)
	}
	// The eShop asking for any other service's token goes to Pretendo: never made up.
	if _, body, _ = do("GET", serviceTokenPath+"?client_id=0123456789abcdef0123456789abcdef", "0004001000020900", ""); body != refusal || pretendoCalls != 1 {
		t.Errorf("other service's token was made up: %s (Pretendo called %d times)", body, pretendoCalls)
	}
	// Any other app's refusal is left alone.
	if _, body, _ = do("GET", serviceTokenPath+"?client_id=abc", "0004000000055D00", ""); body != refusal {
		t.Errorf("non-eShop refusal changed: %s", body)
	}

	// Nothing secret reaches the disk.
	logData, _ := os.ReadFile(filepath.Join(rec.Dir, "events.jsonl"))
	for _, secret := range []string{"SECRET", "Bearer", "Authorization"} {
		if strings.Contains(string(logData), secret) {
			t.Errorf("log contains %q:\n%s", secret, logData)
		}
	}
	if bodies, _ := os.ReadDir(filepath.Join(rec.Dir, "bodies")); len(bodies) != 0 {
		t.Errorf("%d account bodies saved", len(bodies))
	}
}

func TestAccountHostWithProxyOff(t *testing.T) {
	rec := newRec(t)
	front := httptest.NewTLSServer(&Handler{Rec: rec, Listener: "https"})
	defer front.Close()
	req, _ := http.NewRequest("POST", front.URL+"/v1/api/oauth20/access_token/generate", strings.NewReader("password=SECRET"))
	req.Host = AccountHost
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d", resp.StatusCode)
	}
	if bodies, _ := os.ReadDir(filepath.Join(rec.Dir, "bodies")); len(bodies) != 0 {
		t.Error("account body saved with the proxy off")
	}
}
