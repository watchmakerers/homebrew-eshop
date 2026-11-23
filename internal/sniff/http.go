package sniff

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// maxBody caps how much of a request body is kept.
const maxBody = 16 << 20

// Handler records every request. If Responses/<host>/<path> exists it is served with 200 (so we can feed the
// app canned answers while working out the protocol); otherwise the reply is 404.
type Handler struct {
	Rec       *Recorder
	Responses string
	Stubs     *Stubs        // built-in replies, used when there's no canned file (may be nil)
	Account   *AccountProxy // if set, requests to AccountHost go to it (and are never logged in full)
	Listener  string        // "http" or "https", for the log
}

var validHost = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*$`)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	// Before anything reads or saves the body: account traffic carries login credentials.
	if host == AccountHost {
		if h.Account != nil && r.TLS != nil {
			h.Account.ServeHTTP(w, r)
		} else {
			http.Error(w, "account proxy is off", http.StatusBadGateway)
			h.Rec.Record(Event{Kind: "http", Listener: h.Listener, Method: r.Method, Host: host, URI: r.URL.Path, Status: http.StatusBadGateway},
				fmt.Sprintf("%-5s %s %s%s -> 502 (account proxy is off)", h.Listener, r.Method, host, r.URL.Path))
		}
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))

	e := Event{
		Kind: "http", Listener: h.Listener, From: r.RemoteAddr,
		Method: r.Method, Host: host, URI: r.RequestURI, Header: r.Header, BodyLen: len(body),
	}
	if r.TLS != nil {
		e.TLS = &TLSInfo{Version: tls.VersionName(r.TLS.Version), Cipher: tls.CipherSuiteName(r.TLS.CipherSuite)}
		if len(r.TLS.PeerCertificates) > 0 {
			c := r.TLS.PeerCertificates[0]
			e.TLS.ClientCert, e.TLS.ClientCA = c.Subject.String(), c.Issuer.String()
		}
	}
	if len(body) > 0 {
		if name, err := h.Rec.SaveBody(body); err == nil {
			e.BodyFile = name
		}
	}

	e.Status = http.StatusNotFound
	if file := h.responseFile(host, r.URL.Path); file != "" {
		if data, err := os.ReadFile(file); err == nil {
			// Optional sidecar <file>.status holds the status code to send (default 200).
			status := http.StatusOK
			if st, err := os.ReadFile(file + ".status"); err == nil {
				if n, err := strconv.Atoi(strings.TrimSpace(string(st))); err == nil && n >= 200 && n < 600 {
					status = n
				}
			}
			e.Status, e.ServedFile = status, file
			w.Header().Set("Content-Type", contentType(file, data))
			w.WriteHeader(status)
			w.Write(data)
		}
	}
	if e.Status == http.StatusNotFound && h.Stubs != nil {
		if rep := h.Stubs.Respond(host, r, body); rep != nil {
			status := rep.status
			if status == 0 {
				status = http.StatusOK
			}
			e.Status, e.ServedFile = status, "stub: "+rep.name
			for k, v := range rep.header {
				w.Header()[k] = v
			}
			w.Header().Set("Content-Type", rep.contentType)
			if rep.serve != nil {
				rep.serve(w, r)
			} else {
				w.WriteHeader(status)
				w.Write(rep.body)
			}
		}
	}
	if e.Status == http.StatusNotFound {
		http.NotFound(w, r)
	}

	extra := ""
	if e.TLS != nil && e.TLS.ClientCert != "" {
		extra = " [client cert]"
	}
	if len(body) > 0 {
		extra += fmt.Sprintf(" [body %d B]", len(body))
	}
	if e.ServedFile != "" {
		extra += " (" + e.ServedFile + ")"
	}
	h.Rec.Record(e, fmt.Sprintf("%-5s %s %s%s -> %d%s", h.Listener, r.Method, host, r.RequestURI, e.Status, extra))
}

// responseFile maps host+path to a file under Responses, refusing anything that could escape it.
func (h *Handler) responseFile(host, urlPath string) string {
	if h.Responses == "" || !validHost.MatchString(host) {
		return ""
	}
	clean := filepath.Clean("/" + urlPath) // Clean of a rooted path removes every ".."
	if clean == "/" {
		clean = "/index"
	}
	p := filepath.Join(h.Responses, host, filepath.FromSlash(clean))
	if fi, err := os.Stat(p); err != nil || fi.IsDir() {
		return ""
	}
	return p
}

func contentType(file string, data []byte) string {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".xml":
		return "application/xml"
	case ".json":
		return "application/json"
	}
	return http.DetectContentType(data)
}

// LegacyTLSConfig accepts what the 3DS speaks: TLS 1.0 to 1.2 with old RSA cipher suites. Go leaves those
// out by default but allows them when listed explicitly. It also asks for (but doesn't require) a client
// certificate, to see whether the eShop sends one, and records each ClientHello.
func LegacyTLSConfig(cert tls.Certificate, rec *Recorder) *tls.Config {
	var ids []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		for _, v := range s.SupportedVersions {
			if v <= tls.VersionTLS12 {
				ids = append(ids, s.ID)
				break
			}
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: ids,
		ClientAuth:   tls.RequestClientCert,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			e := Event{Kind: "tls_hello", From: hello.Conn.RemoteAddr().String(), SNI: hello.ServerName}
			for _, v := range hello.SupportedVersions {
				e.Versions = append(e.Versions, tls.VersionName(v))
			}
			for _, c := range hello.CipherSuites {
				e.Ciphers = append(e.Ciphers, tls.CipherSuiteName(c))
			}
			line := ""
			if rec.FirstTime("hello:" + hello.ServerName) {
				line = fmt.Sprintf("TLS   hello sni=%q versions=%v (%d ciphers offered)", hello.ServerName, e.Versions, len(e.Ciphers))
			}
			rec.Record(e, line)
			return nil, nil
		},
	}
}
