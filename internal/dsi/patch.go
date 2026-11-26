package dsi

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// PatchShop makes the DSi Shop app (the .app content file from the console's own NAND) trust ca, and
// returns the new .app and title.tmd. Only the ARM9 binary changes; it is stored back uncompressed at the
// end of the file. The result is only for a console running hiyaCFW, which skips the signature and hash
// checks the edited app and TMD no longer pass. Every patch site is found by content and checked, so an
// unexpected shop version fails instead of being patched blindly.
//
//   - The shop's SOAP/HTTPS root CA is read from the signed system archive as "verdata:NintendoCA-G2.der".
//     The format string becomes "nand:/%s.der", so the shop reads NintendoCA-G2.der from the root of the
//     (SD) NAND instead: CAFileName, which the caller copies there.
//   - Nintendo Wi-Fi Connection logins (nas.nintendowifi.net) check against the SSL library's built-in CA
//     table. Its "Nintendo CA" entry gets ca's name and modulus.
func PatchShop(app, tmd []byte, ca *CA) (newApp, newTMD []byte, notes []string, err error) {
	if len(app) < 0x1000 || string(app[0:4]) != "SHOP" {
		return nil, nil, nil, errors.New("not the DSi Shop app (header title isn't SHOP)")
	}
	le := binary.LittleEndian
	a9off, a9ram, a9size := le.Uint32(app[0x20:]), le.Uint32(app[0x28:]), le.Uint32(app[0x2C:])
	if uint64(a9off)+uint64(a9size) > uint64(len(app)) {
		return nil, nil, nil, errors.New("ARM9 lies outside the file")
	}
	arm9 := append([]byte(nil), app[a9off:a9off+a9size]...)

	// Module params: located by their magic; compressed_static_end != 0 means BLZ-compressed.
	mp := bytes.Index(arm9, []byte{0x21, 0x06, 0xC0, 0xDE, 0xDE, 0xC0, 0x06, 0x21})
	if mp < 0x1C {
		return nil, nil, nil, errors.New("ARM9 module params not found")
	}
	mp -= 0x1C
	if end := le.Uint32(arm9[mp+0x14:]); end != 0 {
		if end != a9ram+a9size {
			return nil, nil, nil, fmt.Errorf("compressed end %#x doesn't match the ARM9 end %#x", end, a9ram+a9size)
		}
		if arm9, err = blzDecompress(arm9); err != nil {
			return nil, nil, nil, fmt.Errorf("ARM9: %w", err)
		}
		le.PutUint32(arm9[mp+0x14:], 0)
		notes = append(notes, fmt.Sprintf("ARM9 decompressed: %#x -> %#x bytes", a9size, len(arm9)))
	}

	// 1. verdata:%s.der -> nand:/%s.der
	oldFmt, newFmt := []byte("verdata:%s.der\x00"), []byte("nand:/%s.der\x00")
	if n := bytes.Count(arm9, oldFmt); n != 1 {
		return nil, nil, nil, fmt.Errorf("expected one %q, found %d", oldFmt[:len(oldFmt)-1], n)
	}
	i := bytes.Index(arm9, oldFmt)
	copy(arm9[i:i+len(oldFmt)], make([]byte, len(oldFmt)))
	copy(arm9[i:], newFmt)
	notes = append(notes, fmt.Sprintf("%#x: verdata:%%s.der -> nand:/%%s.der", a9ram+uint32(i)))

	// 2. built-in CA table entry {name*, 0x80, modulus*, 3, exponent*} for "... Nintendo CA ..."
	oldDN := []byte("US, Washington, Nintendo of America Inc, NOA, Nintendo CA, ca@noa.nintendo.com\x00")
	if n := bytes.Count(arm9, oldDN); n != 1 {
		return nil, nil, nil, fmt.Errorf("expected one Nintendo CA table name, found %d", n)
	}
	dnOff := bytes.Index(arm9, oldDN)
	var entry []byte
	for _, want := range [][]byte{le.AppendUint32(nil, a9ram+uint32(dnOff))} {
		for j := 0; j+20 <= len(arm9); j += 4 {
			if bytes.Equal(arm9[j:j+4], want) && le.Uint32(arm9[j+4:]) == 0x80 && le.Uint32(arm9[j+12:]) == 3 {
				if entry != nil {
					return nil, nil, nil, errors.New("more than one Nintendo CA table entry")
				}
				entry = arm9[j : j+20]
			}
		}
	}
	if entry == nil {
		return nil, nil, nil, errors.New("Nintendo CA table entry not found")
	}
	modOff, expOff := int(le.Uint32(entry[8:])-a9ram), int(le.Uint32(entry[16:])-a9ram)
	if modOff < 0 || modOff+0x80 > len(arm9) || expOff < 0 || expOff+3 > len(arm9) {
		return nil, nil, nil, errors.New("CA table pointers out of range")
	}
	if !bytes.Equal(arm9[expOff:expOff+3], []byte{1, 0, 1}) || ca.Key.PublicKey.E != 65537 {
		return nil, nil, nil, errors.New("CA table exponent isn't 65537")
	}
	dn, err := ca.DNString()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(dn)+1 > len(oldDN) {
		return nil, nil, nil, fmt.Errorf("CA name %q is too long for the table (max %d)", dn, len(oldDN)-1)
	}
	copy(arm9[dnOff:dnOff+len(oldDN)], make([]byte, len(oldDN)))
	copy(arm9[dnOff:], dn)
	copy(arm9[modOff:modOff+0x80], ca.Modulus())
	notes = append(notes, fmt.Sprintf("%#x: built-in CA %q -> %q (modulus at %#x)", a9ram+uint32(dnOff), "Nintendo CA", dn, a9ram+uint32(modOff)))

	// Rebuild: the ARM9 goes at the end of the file (it no longer fits where it was), 0x200-aligned.
	out := append([]byte(nil), app...)
	for len(out)%0x200 != 0 {
		out = append(out, 0)
	}
	newOff := uint32(len(out))
	out = append(out, arm9...)
	for len(out)%0x200 != 0 {
		out = append(out, 0)
	}
	le.PutUint32(out[0x20:], newOff)
	le.PutUint32(out[0x2C:], uint32(len(arm9)))
	le.PutUint32(out[0x210:], uint32(len(out))) // TWL: total ROM size
	binary.LittleEndian.PutUint16(out[0x15E:], crc16(out[:0x15E]))
	notes = append(notes, fmt.Sprintf("ARM9 moved %#x -> %#x; app %#x -> %#x bytes", a9off, newOff, len(app), len(out)))

	if newTMD, err = patchTMD(tmd, out); err != nil {
		return nil, nil, nil, err
	}
	return out, newTMD, notes, nil
}

// CAFileName is where the patched shop looks for its root CA: the root of the NAND, which on hiyaCFW is
// the root of the SD card.
const CAFileName = "NintendoCA-G2.der"

// patchTMD sets the (single) content record's size and SHA-1 to match app. TMD layout: 0x140-byte RSA-2048
// signature block, 0xC4-byte header (content count at 0xDE), then 0x24-byte content records.
func patchTMD(tmd, app []byte) ([]byte, error) {
	if len(tmd) < 0x1E4+0x24 || binary.BigEndian.Uint32(tmd[0:]) != 0x00010001 {
		return nil, errors.New("title.tmd: not an RSA-2048 TMD")
	}
	if n := binary.BigEndian.Uint16(tmd[0x140+0x9E:]); n != 1 {
		return nil, fmt.Errorf("title.tmd: %d contents, expected 1", n)
	}
	out := append([]byte(nil), tmd...)
	rec := out[0x1E4 : 0x1E4+0x24]
	binary.BigEndian.PutUint64(rec[8:], uint64(len(app)))
	sum := sha1.Sum(app)
	copy(rec[16:], sum[:])
	return out, nil
}

// crc16 is the CRC-16/MODBUS used for the DS header checksum.
func crc16(b []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, c := range b {
		crc ^= uint16(c)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// blzDecompress undoes Nintendo's backward LZ ("BLZ") used for DS ARM9 binaries. The last 8 bytes are
// {compressed length (24 bits) | footer length << 24, extra size}; data decompresses from the end backwards.
func blzDecompress(d []byte) ([]byte, error) {
	if len(d) < 8 {
		return nil, errors.New("BLZ: too short")
	}
	info, extra := binary.LittleEndian.Uint32(d[len(d)-8:]), binary.LittleEndian.Uint32(d[len(d)-4:])
	hdr, clen := int(info>>24), int(info&0xFFFFFF)
	if hdr < 8 || hdr > 11 || clen > len(d) || clen < hdr {
		return nil, fmt.Errorf("BLZ: bad footer (header %d, length %#x)", hdr, clen)
	}
	start := len(d) - clen
	src := d[start : len(d)-hdr]
	out := make([]byte, clen+int(extra))
	s, o := len(src), len(out)
	for s > 0 && o > 0 {
		s--
		flags := src[s]
		for bit := 0; bit < 8 && s > 0 && o > 0; bit++ {
			if flags&0x80 != 0 {
				if s < 2 {
					return nil, errors.New("BLZ: truncated")
				}
				s -= 2
				v := int(src[s]) | int(src[s+1])<<8
				n, disp := v>>12+3, v&0xFFF+3
				for k := 0; k < n && o > 0; k++ {
					o--
					if o+disp >= len(out) {
						return nil, errors.New("BLZ: bad back-reference")
					}
					out[o] = out[o+disp]
				}
			} else {
				s--
				o--
				out[o] = src[s]
			}
			flags <<= 1
		}
	}
	return append(append([]byte(nil), d[:start]...), out...), nil
}
