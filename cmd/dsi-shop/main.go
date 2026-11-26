// dsi-shop serves the Nintendo DSi Shop app from this PC.
//
//	dsi-shop patch -sd /run/media/$USER/SDCARD   patch the shop on a hiyaCFW SD card to trust this PC
//	dsi-shop serve                              DNS + HTTP(S) for the shop; point the DSi's DNS at this PC
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"homebrew-eshop/internal/dsi"
	"homebrew-eshop/internal/sniff"
)

const shopContent = "title/00030015/484e4645" // US shop; the patch checks the app itself

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dsi-shop patch|serve [flags]  (-h for flags)")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "patch":
		err = patch(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q (patch or serve)", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dsi-shop:", err)
		os.Exit(1)
	}
}

func patch(args []string) error {
	fs := flag.NewFlagSet("patch", flag.ExitOnError)
	sd := fs.String("sd", "", "root of the hiyaCFW SD card (required)")
	caDir := fs.String("ca", "sniff-data/dsi", "where the CA lives (created if missing)")
	restore := fs.Bool("restore", false, "put the original shop back from the .orig backups instead")
	fs.Parse(args)
	if *sd == "" {
		return errors.New("-sd is required")
	}
	dir := filepath.Join(*sd, shopContent, "content")
	app, tmd := filepath.Join(dir, "00000004.app"), filepath.Join(dir, "title.tmd")
	caFile := filepath.Join(*sd, dsi.CAFileName)

	if *restore {
		for _, f := range []string{app, tmd} {
			if err := os.Rename(f+".orig", f); err != nil {
				return err
			}
		}
		os.Remove(caFile)
		fmt.Println("Original DSi Shop restored.")
		return nil
	}

	// Always patch from the original: keep it as .orig the first time, reuse it afterwards.
	for _, f := range []string{app, tmd} {
		if _, err := os.Stat(f + ".orig"); errors.Is(err, os.ErrNotExist) {
			data, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("reading the shop from the SD card: %w", err)
			}
			if err := os.WriteFile(f+".orig", data, 0o644); err != nil {
				return err
			}
		}
	}
	origApp, err := os.ReadFile(app + ".orig")
	if err != nil {
		return err
	}
	origTMD, err := os.ReadFile(tmd + ".orig")
	if err != nil {
		return err
	}
	ca, err := dsi.LoadOrCreateCA(*caDir)
	if err != nil {
		return err
	}
	newApp, newTMD, notes, err := dsi.PatchShop(origApp, origTMD, ca)
	if err != nil {
		return err
	}
	for _, n := range notes {
		fmt.Println(" ", n)
	}
	for f, data := range map[string][]byte{app: newApp, tmd: newTMD, caFile: ca.Cert.Raw} {
		if err := os.WriteFile(f, data, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("Patched shop written to %s (originals kept as .orig), CA at %s.\n", dir, caFile)
	fmt.Println("Undo with: dsi-shop patch -sd", *sd, "-restore")
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var (
		dnsAddr   = fs.String("dns", "auto", "DNS listen address; auto = port 53 on the -answer-ip address")
		upstream  = fs.String("upstream", "1.1.1.1:53", "resolver for hostnames that aren't intercepted")
		answer    = fs.String("answer-ip", "", "IP returned for intercepted hostnames (default: this PC's LAN address)")
		httpAddr  = fs.String("http", ":80", "HTTP listen address")
		httpsAddr = fs.String("https", ":443", "HTTPS listen address")
		caDir     = fs.String("ca", "sniff-data/dsi", "the CA made by `dsi-shop patch`")
		logDir    = fs.String("logdir", "sniff-data/dsi/log", "where events.jsonl and request bodies go")
		responses = fs.String("responses", "sniff-data/dsi/responses", "canned replies: <dir>/<host>/<path>")
		pages     = fs.String("pages", "dsi-pages", "the shop's HTML pages (edited live; index.html is the start page)")
	)
	fs.Parse(args)

	ca, err := dsi.LoadOrCreateCA(*caDir)
	if err != nil {
		return err
	}
	rec, err := sniff.NewRecorder(*logDir, os.Stdout)
	if err != nil {
		return err
	}
	defer rec.Close()

	var ip netip.Addr
	if *answer != "" {
		if ip, err = netip.ParseAddr(*answer); err != nil || !ip.Is4() {
			return fmt.Errorf("-answer-ip %q: need an IPv4 address", *answer)
		}
	} else if ip, err = sniff.LANAddr(*upstream); err != nil {
		return fmt.Errorf("finding this PC's LAN address (set -answer-ip): %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 4)
	var shutdowns []func()

	// DNS, remembering each client's last intercepted lookup: if the DSi sends no SNI, that's the best
	// guess at which host a new TLS connection is for.
	last := &lastLookup{m: map[string]string{}}
	dnsH := &sniff.DNS{Upstream: *upstream, AnswerIP: ip, Patterns: dsi.Patterns, Rec: rec}
	if *dnsAddr == "auto" {
		*dnsAddr = net.JoinHostPort(ip.String(), "53")
	}
	if *dnsAddr != "" {
		h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			if len(req.Question) == 1 {
				name := strings.TrimSuffix(strings.ToLower(req.Question[0].Name), ".")
				if dnsH.Match(name) {
					host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
					last.set(host, name)
				}
			}
			dnsH.ServeDNS(w, req)
		})
		for _, network := range []string{"udp", "tcp"} {
			s := &dns.Server{Addr: *dnsAddr, Net: network, Handler: h}
			go func() { errc <- wrap("dns/"+network, s.ListenAndServe()) }()
			shutdowns = append(shutdowns, func() { s.Shutdown() })
		}
	}

	handler := func(listener string) http.Handler {
		return &dsi.Handler{Rec: rec, Listener: listener, PagesDir: *pages,
			Fallback: &sniff.Handler{Rec: rec, Responses: *responses, Listener: listener}}
	}
	run := func(name string, srv *http.Server, tlsOn bool) {
		srv.ReadHeaderTimeout = 15 * time.Second
		srv.ErrorLog = log.New(rec.Writer(name), "", 0)
		go func() {
			var err error
			if tlsOn {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- wrap(name, err)
			}
		}()
		shutdowns = append(shutdowns, func() { srv.Close() })
	}
	run("http", &http.Server{Addr: *httpAddr, Handler: handler("http")}, false)

	tlsCfg := sniff.LegacyTLSConfig(tls.Certificate{}, rec)
	tlsCfg.Certificates = nil
	tlsCfg.ClientAuth = tls.NoClientCert // the shop has a client cert; we don't need it
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host, how := hello.ServerName, "sni"
		if host == "" {
			remote, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())
			host, how = last.get(remote), "last DNS lookup"
			if host == "" {
				host, how = dsi.PagesHost, "default"
			}
		}
		if rec.FirstTime("cert:" + host + how) {
			rec.Record(sniff.Event{Kind: "tls_cert", SNI: hello.ServerName, Message: host + " (" + how + ")"},
				fmt.Sprintf("TLS   certificate for %s (%s)", host, how))
		}
		return ca.Leaf(host)
	}
	// The shop's browser opens with an SSLv2-format hello, which crypto/tls refuses: dsi.Listener sends
	// those connections to its own TLS 1.0 server and the rest to crypto/tls.
	ln, err := net.Listen("tcp", *httpsAddr)
	if err != nil {
		return wrap("https", err)
	}
	legacy := &dsi.Listener{Listener: ln, Config: tlsCfg,
		Cert: func(remote string) (*tls.Certificate, error) {
			host, how := last.get(remote), "last DNS lookup"
			if host == "" {
				host, how = dsi.PagesHost, "default"
			}
			if rec.FirstTime("cert:" + host + how) {
				rec.Record(sniff.Event{Kind: "tls_cert", Message: host + " (" + how + ", legacy)"},
					fmt.Sprintf("TLS   certificate for %s (%s, legacy)", host, how))
			}
			return ca.Leaf(host)
		},
		Log: func(remote string, info *dsi.LegacyInfo, err error) {
			line := fmt.Sprintf("TLS   legacy %s hello from %s: version %#04x, offered %04x", info.HelloFormat, remote, info.Version, info.Offered)
			if err != nil {
				rec.Record(sniff.Event{Kind: "error", From: remote, Message: line + ": " + err.Error()}, "!! "+line+": "+err.Error())
				return
			}
			if rec.FirstTime("legacy:" + remote + info.Cipher) {
				rec.Record(sniff.Event{Kind: "tls_hello", From: remote, Ciphers: []string{info.Cipher}, Message: line}, line+" -> "+info.Cipher)
			}
		}}
	https := &http.Server{Handler: handler("https"), ReadHeaderTimeout: 15 * time.Second, ErrorLog: log.New(rec.Writer("https"), "", 0)}
	go func() {
		if err := https.Serve(legacy); !errors.Is(err, http.ErrServerClosed) {
			errc <- wrap("https", err)
		}
	}()
	shutdowns = append(shutdowns, func() { https.Close() })

	fmt.Printf("dsi-shop: intercepting %s -> %s\n", strings.Join(dsi.Patterns, ", "), ip)
	fmt.Printf("On the DSi: System Settings > Internet > Connection Settings > your connection > Change Settings > DNS:\n")
	fmt.Printf("  Auto-obtain DNS = No, Primary DNS = %s, Secondary DNS = %s\n", ip, ip)
	fmt.Printf("Then open the Nintendo DSi Shop. Log: %s/events.jsonl. Ctrl-C to stop.\n\n", *logDir)

	select {
	case <-ctx.Done():
		err = nil
	case err = <-errc:
	}
	for _, f := range shutdowns {
		f()
	}
	return err
}

type lastLookup struct {
	mu sync.Mutex
	m  map[string]string
}

func (l *lastLookup) set(ip, name string) { l.mu.Lock(); l.m[ip] = name; l.mu.Unlock() }
func (l *lastLookup) get(ip string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[ip]
}

func wrap(name string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("%s: %w (ports under 1024 need: sudo setcap cap_net_bind_service=+ep <binary>)", name, err)
	}
	return fmt.Errorf("%s: %w", name, err)
}
