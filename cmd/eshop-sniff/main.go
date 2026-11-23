// eshop-sniff logs what the 3DS eShop app requests, for working out the protocol.
//
// Set the 3DS's primary DNS to this PC. eShop hostnames resolve to this PC and every request to them is
// logged; everything else is forwarded to the upstream resolver, so Pretendo/Youmakai logins keep working.
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
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"homebrew-eshop/internal/shopload"
	"homebrew-eshop/internal/sniff"
)

func main() {
	var (
		dnsAddr    = flag.String("dns", "auto", "DNS listen address; auto = port 53 on the -answer-ip address, which avoids systemd-resolved's 127.0.0.53 (empty to disable)")
		upstream   = flag.String("upstream", "1.1.1.1:53", "resolver for hostnames that aren't intercepted")
		answer     = flag.String("answer-ip", "", "IP returned for intercepted hostnames (default: this PC's LAN address)")
		patterns   = flag.String("intercept", strings.Join(sniff.DefaultPatterns, ","), "comma-separated hostname globs to send to this PC")
		allowAny   = flag.Bool("dns-allow-any", false, "answer DNS from non-private addresses (don't expose this to the internet)")
		httpAddr   = flag.String("http", ":80", "HTTP listen address (empty to disable)")
		httpsAddr  = flag.String("https", ":443", "HTTPS listen address (empty to disable)")
		certFile   = flag.String("cert", "sniff-data/tls/cert.pem", "TLS certificate (created if missing)")
		keyFile    = flag.String("key", "sniff-data/tls/key.pem", "TLS key (created if missing)")
		logDir     = flag.String("logdir", "sniff-data/log", "where events.jsonl and request bodies go")
		responses  = flag.String("responses", "sniff-data/responses", "canned replies: <dir>/<host>/<path>")
		noStubs    = flag.Bool("no-stubs", false, "don't answer the eShop's startup requests (only canned files)")
		catalogCfg = flag.String("catalog", "", "eshopd config (e.g. config.yaml): serve its catalog's categories, titles and icons instead of placeholders")
		acctProxy  = flag.Bool("account-proxy", false, "also intercept "+sniff.AccountHost+": forward everything to Pretendo, but answer the eShop's service token request when Pretendo refuses it")
	)
	flag.Parse()
	var stubs *sniff.Stubs
	if !*noStubs {
		stubs = &sniff.Stubs{HashFile: "sniff-data/titlehash"}
	}
	if *catalogCfg != "" && stubs != nil {
		shop, err := shopload.Load(*catalogCfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "eshop-sniff: -catalog:", err)
			os.Exit(1)
		}
		stubs.Shop = shop
	}
	if *acctProxy {
		// The push notification server too: the eShop uses a token we make up with it, which must stay on this PC.
		*patterns += "," + sniff.AccountHost + "," + sniff.NPNSHost
	}
	if err := run(*dnsAddr, *upstream, *answer, *patterns, *allowAny, *httpAddr, *httpsAddr, *certFile, *keyFile, *logDir, *responses, stubs, *acctProxy); err != nil {
		fmt.Fprintln(os.Stderr, "eshop-sniff:", err)
		os.Exit(1)
	}
}

func run(dnsAddr, upstream, answer, patterns string, allowAny bool, httpAddr, httpsAddr, certFile, keyFile, logDir, responses string, stubs *sniff.Stubs, acctProxy bool) error {
	rec, err := sniff.NewRecorder(logDir, os.Stdout)
	if err != nil {
		return err
	}
	defer rec.Close()

	var ip netip.Addr
	if answer != "" {
		if ip, err = netip.ParseAddr(answer); err != nil || !ip.Is4() {
			return fmt.Errorf("-answer-ip %q: need an IPv4 address", answer)
		}
	} else if ip, err = sniff.LANAddr(upstream); err != nil {
		return fmt.Errorf("finding this PC's LAN address (set -answer-ip): %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 4)
	var shutdowns []func()

	if dnsAddr == "auto" {
		dnsAddr = net.JoinHostPort(ip.String(), "53")
	}
	if dnsAddr != "" {
		h := &sniff.DNS{Upstream: upstream, AnswerIP: ip, Patterns: splitList(patterns), AllowAny: allowAny, Rec: rec}
		for _, network := range []string{"udp", "tcp"} {
			s := &dns.Server{Addr: dnsAddr, Net: network, Handler: h}
			go func() { errc <- wrap("dns/"+network, s.ListenAndServe()) }()
			shutdowns = append(shutdowns, func() { s.Shutdown() })
		}
	}

	serve := func(name, addr string, srv *http.Server, tlsOn bool) {
		srv.Addr, srv.ReadHeaderTimeout = addr, 15*time.Second
		srv.ErrorLog = log.New(rec.Writer(name), "", 0) // TLS handshake failures land here
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
	if httpAddr != "" {
		serve("http", httpAddr, &http.Server{Handler: &sniff.Handler{Rec: rec, Responses: responses, Stubs: stubs, Listener: "http"}}, false)
	}
	if httpsAddr != "" {
		cert, err := sniff.LoadOrCreateCert(certFile, keyFile)
		if err != nil {
			return err
		}
		var account *sniff.AccountProxy
		if acctProxy {
			account = sniff.NewAccountProxy(rec)
		}
		serve("https", httpsAddr, &http.Server{
			Handler:   &sniff.Handler{Rec: rec, Responses: responses, Stubs: stubs, Account: account, Listener: "https"},
			TLSConfig: sniff.LegacyTLSConfig(cert, rec),
			// HTTP/1.1 only: Go rejects HTTP/2 over TLS < 1.2, and the 3DS doesn't speak HTTP/2 anyway.
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		}, true)
	}

	fmt.Printf("eshop-sniff: intercepting %s -> %s\n", patterns, ip)
	if acctProxy {
		fmt.Printf("Account proxy on: Pretendo account traffic passes through this PC (only paths and statuses are logged).\n")
		fmt.Printf("Push notifications (%s) also come here, so other apps' notifications won't arrive while this runs.\n", sniff.NPNSHost)
	}
	fmt.Printf("On the 3DS: System Settings > Internet Settings > your connection > Change Settings > DNS:\n")
	fmt.Printf("  Auto-Obtain = No, Primary DNS = %s, Secondary DNS = %s\n", ip, ip)
	fmt.Printf("Then open the eShop. Log: %s/events.jsonl. Ctrl-C to stop.\n\n", logDir)

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

func wrap(name string, err error) error {
	if err == nil {
		return nil
	}
	var op *net.OpError
	if errors.As(err, &op) && errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("%s: %w (ports under 1024 need: sudo setcap cap_net_bind_service=+ep <binary>)", name, err)
	}
	return fmt.Errorf("%s: %w", name, err)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
