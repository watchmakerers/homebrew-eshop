package sniff

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AccountHost is Pretendo's account server, as the console reaches it with Nimbus's patches.
const AccountHost = "account.pretendo.cc"

// AccountProxy sits in front of Pretendo's account server. It answers the eShop's service token request itself
// (Pretendo doesn't know the eShop and its front end refuses proxied requests anyway, so that request never goes
// to Pretendo); the token only ever reaches our own eShop servers. Every other request is forwarded unchanged,
// though Pretendo may refuse those too while they come through here (see README).
//
// This traffic carries the console's Pretendo login (access tokens, password hash), so nothing about it is
// logged beyond method, path, status and what the proxy did. Headers and bodies are never written anywhere.
type AccountProxy struct {
	Upstream string // https://account.pretendo.cc
	Client   *http.Client
	Rec      *Recorder
}

// NewAccountProxy returns a proxy to Pretendo with a client that verifies Pretendo's real certificate and
// doesn't follow redirects (the console gets them as-is).
func NewAccountProxy(rec *Recorder) *AccountProxy {
	return &AccountProxy{
		Upstream: "https://" + AccountHost,
		Rec:      rec,
		Client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// eShop app title IDs per region (JPN, USA, EUR, CHN, KOR, TWN). If the console's turns out to differ, the log
// shows the title ID it sent and nothing is filled in.
var eshopTitleIDs = map[string]bool{
	"0004001000020900": true, "0004001000021900": true, "0004001000022900": true,
	"0004001000026900": true, "0004001000027900": true, "0004001000028900": true,
}

// NPNSHost is the push notification server the eShop connects to after opening its session.
const NPNSHost = "l-npns.app.pretendo.cc"

// Client IDs whose service tokens we make up. Each token may only ever reach a server on this PC, never
// Pretendo: the shop's own (used with our ninja server), and the eShop's push notifications (used with NPNSHost,
// which -account-proxy also sends to this PC). Any other client's token request goes to Pretendo as is.
var eshopClientIDs = map[string]bool{
	"71a6f5d6430ea0183e3917787d717c46": true, // eShop (ninja)
	"24755a2fe31f4d32ab9aa24ce5a2bdac": true, // eShop push notifications (NPNS); asked for even with npns_ready false
}

const serviceTokenPath = "/v1/api/provider/service_token/@me"

var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (p *AccountProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e := Event{Kind: "http", Listener: "https", From: r.RemoteAddr, Method: r.Method, Host: r.Host, URI: r.URL.Path}
	titleID := strings.ToUpper(r.Header.Get("X-Nintendo-Title-Id"))
	isTokenReq := r.URL.Path == serviceTokenPath
	if isTokenReq {
		e.URI += "?client_id=" + r.URL.Query().Get("client_id") // identifies the app's service, not the user
	}

	if isTokenReq && eshopTitleIDs[titleID] && eshopClientIDs[r.URL.Query().Get("client_id")] {
		tok := make([]byte, 96)
		rand.Read(tok)
		body := []byte(`<?xml version="1.0"?><service_token><token>` + base64.StdEncoding.EncodeToString(tok) + `</token></service_token>`)
		w.Header().Set("Content-Type", "application/xml;charset=UTF-8")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Write(body)
		e.Status, e.ServedFile = http.StatusOK, "eShop token answered here, not sent to Pretendo"
		p.Rec.Record(e, fmt.Sprintf("acct  %s %s%s -> 200 (%s) title=%s", r.Method, r.Host, e.URI, e.ServedFile, titleID))
		return
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, p.Upstream+r.URL.RequestURI(), r.Body)
	if err != nil {
		p.fail(w, e, err)
		return
	}
	out.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	out.ContentLength = r.ContentLength

	resp, err := p.Client.Do(out)
	if err != nil {
		p.fail(w, e, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		p.fail(w, e, err)
		return
	}

	// Pretendo sends this refusal with status 200, so look at the body.
	refused := bytes.Contains(body, []byte("<errors>"))
	action := "proxied to Pretendo"
	if isTokenReq && refused {
		action = "proxied to Pretendo, token refused and left as is"
	}
	if resp.StatusCode == http.StatusForbidden {
		// Pretendo's front end turning the proxied request away (not its account code). Server says which layer.
		action = "proxied, but Pretendo's front end refused it (server: " + resp.Header.Get("Server") + ")"
		if strings.HasPrefix(r.URL.Path, "/v1/api/oauth20/") {
			// Pretendo never accepts a login through this proxy. The console only logs in when its saved login
			// (about an hour) has expired, so it has to log in once directly.
			action += ". YOUR 3DS NEEDS A FRESH PRETENDO LOGIN: stop eshop-sniff, run it without -account-proxy, " +
				"open the eShop once (it stops at 022-2482, that's fine), then run with -account-proxy again"
		}
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	for _, h := range hopHeaders {
		w.Header().Del(h)
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(resp.StatusCode)
	w.Write(body)

	e.Status, e.ServedFile = resp.StatusCode, action
	line := fmt.Sprintf("acct  %s %s%s -> %d (%s)", r.Method, r.Host, e.URI, resp.StatusCode, action)
	if isTokenReq {
		line += " title=" + titleID
	}
	p.Rec.Record(e, line)
}

func (p *AccountProxy) fail(w http.ResponseWriter, e Event, err error) {
	e.Status, e.ServedFile = http.StatusBadGateway, "Pretendo unreachable: "+err.Error()
	http.Error(w, "upstream error", http.StatusBadGateway)
	p.Rec.Record(e, fmt.Sprintf("acct  %s %s%s -> 502 (Pretendo unreachable: %v)", e.Method, e.Host, e.URI, err))
}
