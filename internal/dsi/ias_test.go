package dsi

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"homebrew-eshop/internal/sniff"
)

func TestGenerateKeyPair(t *testing.T) {
	rec, err := sniff.NewRecorder(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Rec: rec, Listener: "test"}
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:ias="urn:ias.wsapi.broadon.com">
<SOAP-ENV:Body><ias:GenerateKeyPair>
  <ias:Version>2.0</ias:Version>
  <ias:MessageId>ECSHOP--6557400</ias:MessageId>
  <ias:Region>USA</ias:Region><ias:Country>US</ias:Country>
  <ias:UniqueId>585493622980907302</ias:UniqueId>
</ias:GenerateKeyPair></SOAP-ENV:Body></SOAP-ENV:Envelope>`
	r := httptest.NewRequest("POST", "https://ias.t.shop.nintendowifi.net/ias/services/IdentityAuthenticationSOAP", strings.NewReader(reqBody))
	r.Header.Set("SOAPAction", `"urn:ias.wsapi.broadon.com/GenerateKeyPair"`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"<GenerateKeyPairResponse", "<ErrorCode>0</ErrorCode>", "<MessageId>ECSHOP--6557400</MessageId>", "<DeviceKey>", "<DeviceCert>", "<CertChain>"} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
	// DeviceKey decodes to 0x1E bytes; each cert to 0x180 bytes.
	if got := decodeLen(t, body, "DeviceKey"); got != 0x1E {
		t.Errorf("DeviceKey %d bytes, want 0x1E", got)
	}
	if got := decodeLen(t, body, "DeviceCert"); got != 0x180 {
		t.Errorf("DeviceCert %d bytes, want 0x180", got)
	}
	// The device cert's Key Name (offset 0xC4) must be "TW<8hex>-<16hex console id>", with the 16-hex
	// equal to the UniqueId (585493622980907302 = 0x0820175918089126). The console checks this at import.
	cert := decodeField(t, body, "DeviceCert")
	name := string(cert[0xC4 : 0xC4+0x40])
	name = strings.TrimRight(name, "\x00")
	if !strings.HasPrefix(name, "TW") || !strings.HasSuffix(name, "-0820175918089126") {
		t.Errorf("device cert name %q: want TW<8hex>-0820175918089126", name)
	}
	if issuer := strings.TrimRight(string(cert[0x80:0xC0]), "\x00"); issuer != "Root-CA00000001-MS00000008" {
		t.Errorf("device cert issuer %q", issuer)
	}
	if n := strings.Count(body, "<CertChain>"); n != 2 {
		t.Errorf("%d CertChain elements, want 2", n)
	}
	// ConfirmKeyPair must also answer.
	r2 := httptest.NewRequest("POST", "https://ias.t.shop.nintendowifi.net/ias/services/IdentityAuthenticationSOAP", strings.NewReader(reqBody))
	r2.Header.Set("SOAPAction", `"urn:ias.wsapi.broadon.com/ConfirmKeyPair"`)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), "<ConfirmKeyPairResponse") {
		t.Fatalf("ConfirmKeyPair: status %d body %.200s", w2.Code, w2.Body.String())
	}
}

func decodeField(t *testing.T, body, tag string) []byte {
	t.Helper()
	open, closeTag := "<"+tag+">", "</"+tag+">"
	i := strings.Index(body, open)
	j := strings.Index(body, closeTag)
	if i < 0 || j < 0 {
		t.Fatalf("no %s", tag)
	}
	b, err := base64.StdEncoding.DecodeString(body[i+len(open) : j])
	if err != nil {
		t.Fatalf("%s base64: %v", tag, err)
	}
	return b
}

func decodeLen(t *testing.T, body, tag string) int {
	return len(decodeField(t, body, tag))
}
