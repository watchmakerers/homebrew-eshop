package dsi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"homebrew-eshop/internal/sniff"
)

// Hostnames the DSi Shop uses. Globs as in sniff.DNS (a * doesn't cross dots).
var Patterns = []string{
	ConntestHost, NASHost,
	"*.shop.nintendowifi.net", "*.t.shop.nintendowifi.net",
}

const (
	ConntestHost = "conntest.nintendowifi.net"
	NASHost      = "nas.nintendowifi.net"
	PagesHost    = "tss.t.shop.nintendowifi.net"
)

// Handler answers the DSi Shop's requests that we understand and passes the rest to Fallback (sniff's
// logging handler, which serves canned files from its responses dir or 404s). Everything is logged.
type Handler struct {
	Rec      *sniff.Recorder
	Fallback http.Handler
	Listener string
	// PagesDir holds the shop's HTML pages (tss.*), read on every request so they can be edited while the
	// server runs. "/" and "/index_u" serve index.html. Missing files fall back to the placeholder page.
	PagesDir string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	switch {
	case host == ConntestHost:
		h.conntest(w, r)
	case host == NASHost && r.URL.Path == "/ac":
		h.nas(w, r)
	case host == PagesHost:
		h.pages(w, r)
	default:
		h.Fallback.ServeHTTP(w, r)
	}
}

func (h *Handler) log(r *http.Request, status int, note string) {
	e := sniff.Event{Kind: "http", Listener: h.Listener, From: r.RemoteAddr, Method: r.Method, Host: r.Host, URI: r.RequestURI, Header: r.Header, Status: status, Message: note}
	h.Rec.Record(e, fmt.Sprintf("%-5s %s %s%s -> %d %s", h.Listener, r.Method, r.Host, r.RequestURI, status, note))
}

// conntest: the connection test only wants a 200 with this header.
func (h *Handler) conntest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Organization", "Nintendo")
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, "<html><head><title>HTML Page</title></head><body bgcolor=\"#FFFFFF\">This is test.html page</body></html>")
	h.log(r, 200, "(conntest)")
}

// nas answers Nintendo Wi-Fi Connection's account server. Requests and replies are form fields whose values
// are base64 with '*' for '='. We accept everyone: the shop only needs the login to succeed.
func (h *Handler) nas(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	form, _ := url.ParseQuery(string(body))
	fields := map[string]string{}
	for k, v := range form {
		if len(v) > 0 {
			fields[k] = nasDecode(v[0])
		}
	}
	action := strings.ToLower(fields["action"])
	now := time.Now().UTC().Format("20060102150405")
	reply := map[string]string{"datetime": now}
	switch action {
	case "acctcreate":
		reply["returncd"], reply["userid"] = "002", "1"
	case "login":
		reply["returncd"], reply["locator"] = "001", "gamespy.com"
		reply["challenge"], reply["token"] = randHex(4), "NDS"+randHex(48)
	case "svcloc":
		reply["returncd"], reply["statusdata"], reply["svchost"] = "007", "Y", "n/a"
		reply["servicetoken"], reply["token"] = "NDS"+randHex(48), "NDS"+randHex(48)
	default:
		reply["returncd"] = "001"
	}
	var parts []string
	for k, v := range reply {
		parts = append(parts, k+"="+nasEncode(v))
	}
	sort.Strings(parts)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("NODE", "wifiappe1")
	io.WriteString(w, strings.Join(parts, "&")+"\r\n")

	// Log the decoded fields, minus the password-like ones.
	var shown []string
	for k, v := range fields {
		if k == "passwd" || k == "pw" {
			v = "(hidden)"
		}
		shown = append(shown, k+"="+v)
	}
	sort.Strings(shown)
	h.log(r, 200, fmt.Sprintf("(nas %s -> %s) %s", action, reply["returncd"], strings.Join(shown, " ")))
}

func nasDecode(s string) string {
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(s, "*", "="))
	if err != nil {
		return s
	}
	return string(b)
}

func nasEncode(s string) string {
	return strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(s)), "=", "*")
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handler) pages(w http.ResponseWriter, r *http.Request) {
	// Pages post what they find out to /report (a debugging channel): log the body.
	if r.URL.Path == "/report" {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if r.URL.RawQuery != "" {
			if q, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
				body = append([]byte(q+"\n"), body...)
			}
		}
		file, _ := h.Rec.SaveBody(body)
		w.WriteHeader(http.StatusNoContent)
		h.Rec.Record(sniff.Event{Kind: "report", From: r.RemoteAddr, BodyFile: file, BodyLen: len(body), Message: string(body)},
			fmt.Sprintf("REPORT (%d B, %s)\n%s", len(body), file, indent(string(body))))
		return
	}
	name := path.Clean("/" + r.URL.Path)
	if name == "/" || name == "/index_u" {
		name = "/index.html"
	}
	if h.PagesDir != "" {
		f := filepath.Join(h.PagesDir, filepath.FromSlash(name))
		if data, err := os.ReadFile(f); err == nil {
			ct := mime.TypeByExtension(filepath.Ext(f))
			if ct == "" {
				ct = http.DetectContentType(data)
			}
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Cache-Control", "no-store")
			w.Write(data)
			h.log(r, 200, "(pages"+name+")")
			return
		}
	}
	if name != "/index.html" {
		http.NotFound(w, r)
		h.log(r, 404, "")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, placeholderPage, time.Now().Format("2006-01-02 15:04:05"))
	h.log(r, 200, "(placeholder page)")
}

func indent(s string) string {
	s = strings.TrimRight(s, "\n")
	if len(s) > 4000 {
		s = s[:4000] + "\n..."
	}
	return "      " + strings.ReplaceAll(s, "\n", "\n      ")
}

// placeholderPage proves the patched shop reached us. It also lists what the page's script can see, so the
// first test tells us which EC objects the DSi exposes.
const placeholderPage = `<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>homebrew-eshop</title></head>
<body bgcolor="#ffffff" style="font-family:sans-serif">
<h3>homebrew-eshop DSi Shop</h3>
<p>Connected to your PC. Server time %s.</p>
<pre id="info">checking...</pre>
<script type="text/javascript">
var out = [];
try { out.push("UA: " + navigator.userAgent); } catch (e) {}
var names = ["ec", "ECommerceInterface", "ECCommerce", "shop", "wiiShop", "twlShop", "external", "sound", "trace"];
for (var i = 0; i < names.length; i++) {
  try { out.push(names[i] + ": " + typeof window[names[i]]); } catch (e) { out.push(names[i] + ": error"); }
}
var g = [];
try { for (var k in window) { g.push(k); } } catch (e) {}
out.push("globals: " + g.join(" "));
document.getElementById("info").innerHTML = out.join("\n");
try { var img = new Image(); img.src = "/report?" + encodeURIComponent(out.join("|")); } catch (e) {}
</script>
</body></html>`
