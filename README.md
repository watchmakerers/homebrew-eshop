# homebrew-eshop

A replacement server for the 3DS eShop app that serves homebrew. The console's own eShop app connects to it
(Pretendo-style), so nothing from Nintendo is copied or shipped.

## Status

- [x] **Source layer**: configurable catalog sources (`config.yaml`), merged by title ID or name, by priority, with a disk cache
  for when a source is down.
  - `unistore`: any Universal-Updater store; the install script is followed to find the CIA
  - `github`: latest release of a repo
  - `local`: a folder of `.cia` files (title ID, name and publisher read from the CIA)
  - `backups`: your own dumps of games you own, shown under "My Backups". Same as `local`, but kept apart from
    the homebrew listings. They're only ever served from this PC to your console.
- [ ] eShop protocol research (which hosts and endpoints the app calls on launch, browsing, download): `eshop-sniff`, below
- [ ] Redirect: an http patch variant in Youmakai Network's Nimbus fork (`../Projects/youmakai-network/nimbus-ykw3`),
  whose http patch already rewrites `nintendo.net` hosts
- [ ] eShop-facing endpoints serving the merged catalog
- [ ] Installs: CIA download and ticket flow
  - [x] CDN: `/ccs/download/<title ID>/tmd` and `/<content ID>` served from CIAs on disk (`local`, `backups`)
  - [ ] Ticket delivery (ECS) and whatever the eShop needs before it starts a download
  - [x] Remote CIAs (UniStore/GitHub): downloaded on first view of the title page into `<cache_dir>/cia/`
    (direct links, release assets, one `.zip` level), refreshed after 24h
- [x] Shop artwork: category banners and tiles, title banners, "New" ribbons (updated in the last 30 days) and
  the ticker. Generated from each category's and app's own icons unless you supply your own in `art/` (see
  `art/README.md`)
- [ ] Icons: UniStore icons are in `.t3x` sheets, not decoded yet. Titles with no online artwork (local CIAs,
  backups) use the icon from their CIA's SMDH

## Running

```
cp config.example.yaml config.yaml
go run ./cmd/eshopd -dump          # fetch every source once and print a summary
go run ./cmd/eshopd                # serve /debug/catalog (?installable=1) and /debug/sources
go test ./...
```

## eshop-sniff: logging what the eShop app asks for

A DNS server sends eShop hostnames (`*.shop.nintendo.net`, `*.shop.nintendowifi.net` and the `*.shop.pretendo.cc`
spellings that Nimbus's http patch rewrites them to) to this PC, and an HTTP/HTTPS server logs every request to them.
All other lookups go to a normal resolver, so Pretendo/Youmakai logins keep working. Every lookup is logged either way,
so the log shows every host the eShop touches.

```
go build -o eshop-sniff ./cmd/eshop-sniff
sudo setcap cap_net_bind_service=+ep ./eshop-sniff    # lets it use ports 53, 80 and 443 without root
./eshop-sniff                                         # prints the DNS address to put on the 3DS
```

On the 3DS: Nimbus set to Pretendo or Youmakai Network (for the SSL patch), then System Settings > Internet
Settings > your connection > Change Settings > DNS > Auto-Obtain No, both DNS = the address it printed.
Open the eShop and browse around. Set DNS back to Auto-Obtain afterwards.

- Log: `sniff-data/log/events.jsonl` (DNS lookups, TLS hellos, every request with headers), bodies in `sniff-data/log/bodies/`.
  These contain your console's identifiers and certificates, so keep them to yourself.
- Canned replies: `sniff-data/responses/<host>/<path>` is served with 200, everything else gets 404. That's how we feed
  the app answers one step at a time.
- Hosts outside the default list: `-intercept '*.shop.pretendo.cc,kanzashi-ctr.cdn.pretendo.cc'`.
- DNS only answers private/LAN addresses. Don't port-forward 53.
