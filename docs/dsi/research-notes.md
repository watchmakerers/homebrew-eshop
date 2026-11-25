# DSi Shop revival: research notes

Started 2026-11-25. Scope matches ~/homebrew-eshop: homebrew plus the user's own DSiWare backups, no pirated DSiWare.
Goal: run the real DSi Shop app (on the hiyaCFW SDNAND) against our own server, likely as a DSi mode in ~/homebrew-eshop.

## Prior art (refs/, read-only, nothing run)
- **DSi-ShopPP** (NintendoBrew): frozen. Contains only a website and a copy of the shop app. No server code.
- **DSeShop** (LumoTV): a 65-line Flask toy that serves invented XML. Not the real protocol.
- **DSI-SHOP-RV** (IAmDazen, TESTING branch): only a test .nds. No server.
- **DSiMart** (dsimart.org): private beta, closed source, modeled on WiiMart. Its "Aug 2026" ETA has passed.
=> No usable public DSi reference. The Wii Shop is the real reference (see below).

## The shop app (extracted from the user's own NAND)
- NAND backup: ~/Documents/DT304D03D45960502D/nand.bin (US DSi, no$GBA footer).
- Decrypted copy: nand/nand_dec.bin. The TWL main FS is in nand/fs (`twltool nandcrypt` + `fatcat -O 1109504 -x`).
  **Contains console-unique data. Keep it local and never upload it.**
- Shop title: `00030015/484e4645` (HNFE, US). Content is `content/00000004.app` (5.4 MB). The save is `data/private.sav`.
- Extraction: `twltool modcrypt` → tools/srl_extract.py → tools/blz.py (ARM9 and ARM9i are BLZ-compressed).
  Output is in shop-HNFE/dec/*.dec.bin, NitroFS is in shop-HNFE/data, and strings are in shop-HNFE/arm9.strings.
- ARM9 loads at 0x02004000 (0xd1bb7 bytes decompressed). ARM9i loads at 0x02400000.

## What it is
- **ECSHOP 3.6.0 (Feb 16 2009)**: the same EC library as the Wii Shop Channel (ec_shop.cpp, ec_soap.cpp).
  The UI is the built-in Opera browser loading HTML from the server. The pages drive the EC library via JS (setWebSvcUrls and similar).
- Hosts in the code:
  - `https://tss.t.shop.nintendowifi.net/index_u` is the shop start page (u = US).
  - `ecsUrl/iasUrl/casUrl/ccsUrl/ucsUrl` are set by the pages (setWebSvcUrls). **It refuses non-https URLs** ("setWebSvcUrls was denied request to set non-https URL").
  - `https://nas.nintendowifi.net/ac` is the WFC NAS login (also the .dev and .test variants).
  - `http://conntest.nintendowifi.net/` is the connection test.
  - A Wii leftover: `https://ecs.shop.wii.com/ecs/services/ECommerceSOAP`.
- SOAP actions seen: CheckDeviceStatus, CheckRegistration, GetRegistrationInfo, Register, SyncRegistration, Unregister,
  GetChallenge, GetECConfig, ListTitles, ListContentSets, PurchaseTitle, PurchasePoints, GiftTitle, AcceptGiftTitle,
  ListETickets, GetETickets, DeleteETickets, NotifyETicketsSynced, CheckAccountBalance, SyncTime, Transfer.
  This is the Wii Shop protocol (ECS/IAS/CAS), so Wii Shop reimplementations are the reference.
- Downloads use ContentPrefixURL / UncachedContentPrefixURL (the CCS/UCS content servers, NUS-style). Tickets come from GetETickets
  ("expected at least 2 ticket certs"). The device cert comes from ES_GetDeviceCert.

## HTTPS: patch plan
- The app embeds its own root CAs (a DER blob at arm9.dec.bin 0xbd6f3 contains "Nintendo CA", plus "NintendoCA-G2", "twl-shop-cert"),
  and passes them via NHTTPSetRootCA / NHTTPSetClientCert / NHTTPSetVerifyOption.
- Plan: replace the embedded Nintendo CA with our own same-size RSA CA (or neuter NHTTPSetVerifyOption). Rebuild the .app
  (uncompressed ARM9 + fixed header, or recompressed) and put it **only on the SDNAND copy**. hiyaCFW skips signature checks.
- NAS: we must answer `nas.nintendowifi.net/ac` ourselves (or via a WFC replacement), using the same DNS-intercept approach as eshop-sniff.

## Wii Shop reference: WiiSOAP (refs/WiiSOAP)
- github.com/OpenShopChannel/WiiSOAP: a Go ECS/IAS/CAS server (last updated Apr 2024). **AGPL-3.0**: use it as a
  reference for reply formats. Copying its code would make our server AGPL, so ask the user before doing that.
- Handles: CheckDeviceStatus, CheckRegistration, GetChallenge, GetECConfig, GetETickets, GetRegistrationInfo,
  ListETickets, ListItems, ListPurchaseHistory, NotifyETicketsSynced, PurchaseTitle, Register, SyncRegistration, SyncTime.
  This covers nearly every DSi action. Not covered: ListTitles/ListContentSets (DSi CAS), points/gift, Unregister.
- JS API docs (the pages call ec.*): https://docs.oscwii.org/wii-shop-channel/js/ec/ecommerceinterface
- WiiMart (wiimart.org, github.com/WiiMart) is an active Wii Shop revival written in Java. Check whether it has page/SOAP code.

## Next steps
1. Diff WiiSOAP's replies against the DSi's parsers (DSi is EC 3.6.0; check the version field and namespaces).
2. Disassemble ARM9 (capstone, ARM/Thumb at 0x02004000): NHTTPSetRootCA call site, NAS request fields, initial URL source.
3. Add a DSi mode to eshop-sniff: tss pages, ECS/IAS/CAS SOAP, NAS stub, CCS content, plus a TAD/.nds → content/ticket path for homebrew.
4. Build the patched shop .app and test on the DSi (DNS in DSi Wi-Fi settings → PC).

## Findings, 2026-11-25 (later)
- blz.py fixed: the output region is clen+extra (it was 9 bytes short). Decompressed ARM9 is 0xd1bc0.
- **EC/SOAP root CA** is NOT the embedded copy. Function 0x200f3d8 loads `verdata:NintendoCA-G2.der` via 0x2069b50
  (format string 'verdata:%s.der' at 0x20c1b94). The client cert/key come from `verdata:.twl-shop-cert.der` / `.twl-shop-prvkey.der` (0x2069bc8).
  verdata = system title 0003000f/484e4c45 (HNLE): a 0x80-byte RSA signature + NARC (also holds nup_host.bin, eula_url.bin). Signed, so don't patch it.
  **Patch P1:** 'verdata:%s.der' -> 'nand:/%s.der'. The shop then loads SD:/NintendoCA-G2.der on hiyaCFW, which is our CA.
- The embedded G2 copy (DER at 0x20c16fc, record {size 0x495, ptr} at 0x20c16f4) goes to 0x201ad04 from 0x200fa28 (purpose TBD).
- The cipher list next to it is AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA:RC4-SHA:RC4-MD5, so Go's LegacyTLSConfig should work.
- **NAS (DWC auth)** uses the built-in CA table. The "Nintendo CA" entry is at 0x20ad388: {dn 0x20ad39c
  "US, Washington, Nintendo of America Inc, NOA, Nintendo CA, ca@noa.nintendo.com", modlen 0x80, mod 0x20ad3ec, explen 3, exp 0x20ad384}.
  **Patch P2:** DN string (value list joined by ", " in RDN order) + 1024-bit modulus -> our CA.
- One CA serves both: RSA-1024, sha1WithRSA (the SSL lib has only SHA1/MD5). Go's x509 can still create SHA1WithRSA certs (tested).
- ARM9 module params at 0x2004fac: compressed_static_end = 0x2098780. Set it to 0 for an uncompressed ARM9.
- Rebuild plan: append the uncompressed patched ARM9 at the end of the .app (0x526400), update header 0x20/0x2C/0x210 and CRC 0x15E,
  and update the content size/SHA1 in title.tmd. Leave the modcrypt areas (arm9i/arm7i) untouched.
  RISK: header digest tables (0x1f0..) / RSA no longer match. This relies on hiyaCFW's signature patches. Unverified; keep the original .app on the SD.
- DNS also needs conntest.nintendowifi.net (X-Organization: Nintendo) and nas.nintendowifi.net (DWC form, base64 '*'-padded fields).
- Code plan (worktree ~/homebrew-eshop-dsi, branch dsi-shop): internal/dsi {ca.go, patch.go, nas.go, shop.go}, cmd/dsi-shop, cmd/dsi-shop-patch.
