# Next session with the 3DS

Everything below is ready on the PC. Do the steps in order; each one says what to tell Claude.

## 0. Start the server (PC)

```sh
cd ~/homebrew-eshop
sudo setcap cap_net_bind_service=+ep ./eshop-sniff   # every rebuild drops this
./eshop-sniff -catalog config.yaml
```

The 3DS's DNS must point at this PC (it prints the address). Keep the terminal open: its log is how we see what
happened.

## 1. Music test (5 minutes)

Extdata on the SD card is encrypted per console, so the files go in through a JKSV backup instead:

1. JKSV → Extra Data → Nintendo eShop: back it up once (done 2026-11-23: it held Nintendo's last `boss_bgm1`/
   `boss_xml1`, now also in `bgm/archive/extdata`). Start ftpd and tell Claude the address.
2. Claude puts `boss_bgm1`, `boss_xml1`, `boss_bgm2`, `boss_xml2` in a new backup folder `homebrew-bgm`
   (`JKSV/ExtData/Nintendo eShop/homebrew-bgm`). In JKSV, restore that folder.
3. Open the eShop (any date from November 1 to December 31). You should hear the December 2015 track.
4. To hear the next season early, set the 3DS clock to January (and back afterwards).

If it doesn't play: tell Claude. Restoring the dated backup folder puts Nintendo's track back.

## 2. Install test (10 minutes)

1. Open the eShop, pick a homebrew title (or a game you put in `backups/`), tap download.
2. Whatever happens, **tell Claude the error code** (or that it worked). The server log shows which request it
   stopped at.

New code paths being tried for the first time: CAS `ListTitlesEx`, ninja `prepurchase_info` and `!purchase`,
ECS `AccountGetETickets`, and the CDN download.

## 3. Dumps for emulator testing (15 minutes, optional)

These let Claude test the shop in Azahar without your 3DS next time (browsing, title pages, prices; installs
still need the real console):

1. **The eShop app** as a decrypted CIA: GodMode9 → `SYSNAND` → title manager → Nintendo eShop
   (`0004001000020900`) → *Build CIA (decrypted)*. Copy the `.cia` from `gm9/out` to the PC.
2. **System files**: in Azahar on the PC, `File` → `Set Up System Files`, and run the Artic Setup Tool on the
   3DS (both on the same Wi-Fi). It copies what the emulator needs from your own console.
3. **Hosts entries** (once, on the PC) so the emulated eShop reaches this server instead of Nintendo's:
   Claude will give you the exact `sudo` line.

## 4. SpotPass key (later)

For the music to rotate by itself over SpotPass, the server needs the BOSS AES key from your own console. Work
out the dump method together with Claude (it won't download keys). Once you have it in a file:

```sh
BOSS_KEY_FILE=path/to/key.txt go test ./internal/boss -v -run Archived
```

A pass proves the key is right (it decrypts the archived Nintendo track). Then:
`./eshop-sniff -catalog config.yaml -bgm bgm/calendar.yaml -boss-key path/to/key.txt`
