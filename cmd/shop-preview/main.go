// shop-preview serves a browser view of the shop: the categories, title lists, title pages and images exactly
// as the console would get them. It never downloads CIAs (title IDs of remote titles show as placeholders).
//
//	go run ./cmd/shop-preview [-catalog config.yaml] [-listen 127.0.0.1:8099,100.x.y.z:8099]
//
// Keep it on localhost or a private network (e.g. Tailscale): it has no login.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"homebrew-eshop/internal/shopload"
)

func main() {
	cfg := flag.String("catalog", "config.yaml", "eshopd config")
	listen := flag.String("listen", "127.0.0.1:8099", "comma-separated listen addresses")
	flag.Parse()
	shop, err := shopload.Load(*cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shop-preview:", err)
		os.Exit(1)
	}
	shop.CIAs = nil // never download CIAs for a preview
	h := shop.Preview()
	errc := make(chan error)
	for _, a := range strings.Split(*listen, ",") {
		a := strings.TrimSpace(a)
		fmt.Printf("preview: http://%s/\n", a)
		go func() { errc <- http.ListenAndServe(a, h) }()
	}
	fmt.Fprintln(os.Stderr, "shop-preview:", <-errc)
	os.Exit(1)
}
