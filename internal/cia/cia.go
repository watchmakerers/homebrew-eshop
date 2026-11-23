// Package cia reads the parts of a CIA that installing it through the eShop needs: the ticket, the TMD, each
// content's place in the file, and the SMDH (names and icon) from the meta section.
//
// Layouts are from 3dbrew: "CIA", "Title metadata", "Certificates" and "SMDH".
//
// CIA: a little-endian header (header, cert chain, ticket, TMD, meta sizes and the content size), then the
// cert chain, ticket, TMD, content data and meta, each starting on a 64-byte boundary. Contents follow each other
// in the content data section, in TMD order, skipping any whose bit is clear in the header's content index.
package cia

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"unicode/utf16"
)

const headerSize = 0x2020

// File is a parsed CIA. Byte slices are copies; contents are read from R on demand.
type File struct {
	R io.ReaderAt

	TitleID      uint64
	TitleVersion uint16
	Ticket       []byte // the whole ticket section, signature included
	TMD          []byte // the whole TMD section, signature included
	Certs        []byte // the cert chain section
	Contents     []Content
	SMDH         *SMDH // nil when the CIA has no meta section
}

// Content is one content chunk record plus where its data sits in the CIA.
type Content struct {
	ID     uint32
	Index  uint16
	Type   uint16 // bit 0: encrypted with the title key
	Size   uint64
	Hash   [32]byte
	Offset int64 // in the CIA; -1 when this content isn't in the file
}

func (c Content) Encrypted() bool { return c.Type&1 != 0 }
func (c Content) Present() bool   { return c.Offset >= 0 }

// Reader returns the content's bytes as stored in the CIA.
func (f *File) Reader(c Content) *io.SectionReader {
	return io.NewSectionReader(f.R, c.Offset, int64(c.Size))
}

// Content finds a content by its ID.
func (f *File) Content(id uint32) (Content, bool) {
	for _, c := range f.Contents {
		if c.ID == id {
			return c, true
		}
	}
	return Content{}, false
}

// Parse reads a CIA's header, ticket, TMD and meta.
func Parse(r io.ReaderAt) (*File, error) {
	hdr := make([]byte, headerSize)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("cia header: %w", err)
	}
	if binary.LittleEndian.Uint32(hdr[0x00:]) != headerSize {
		return nil, errors.New("not a CIA (header size isn't 0x2020)")
	}
	certSize := uint64(binary.LittleEndian.Uint32(hdr[0x08:]))
	ticketSize := uint64(binary.LittleEndian.Uint32(hdr[0x0C:]))
	tmdSize := uint64(binary.LittleEndian.Uint32(hdr[0x10:]))
	metaSize := uint64(binary.LittleEndian.Uint32(hdr[0x14:]))
	contentSize := binary.LittleEndian.Uint64(hdr[0x18:])
	index := hdr[0x20:headerSize]

	certOff := align64(headerSize)
	ticketOff := certOff + align64(certSize)
	tmdOff := ticketOff + align64(ticketSize)
	contentOff := tmdOff + align64(tmdSize)
	metaOff := contentOff + align64(contentSize)

	f := &File{R: r}
	var err error
	if f.Certs, err = readSection(r, certOff, certSize, "cert chain"); err != nil {
		return nil, err
	}
	if f.Ticket, err = readSection(r, ticketOff, ticketSize, "ticket"); err != nil {
		return nil, err
	}
	if f.TMD, err = readSection(r, tmdOff, tmdSize, "tmd"); err != nil {
		return nil, err
	}
	if err := f.parseTMD(index, int64(contentOff), contentSize); err != nil {
		return nil, err
	}
	if metaSize >= metaSMDHOffset+smdhSize {
		// Unreadable meta is left out rather than failing: callers may parse just the start of a CIA (see
		// ciacache.Info) to read the TMD without the contents and meta that follow it.
		if meta, err := readSection(r, metaOff, metaSize, "meta"); err == nil {
			if s, err := ParseSMDH(meta[metaSMDHOffset:]); err == nil {
				f.SMDH = s
			}
		}
	}
	return f, nil
}

func readSection(r io.ReaderAt, off, size uint64, what string) ([]byte, error) {
	if size > 64<<20 {
		return nil, fmt.Errorf("%s: implausible size %d", what, size)
	}
	b := make([]byte, size)
	if _, err := r.ReadAt(b, int64(off)); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return b, nil
}

// SignatureLen is the size of a signature block (type, signature, padding) from its big-endian type.
func SignatureLen(sigType uint32) (int, error) {
	switch sigType {
	case 0x10000, 0x10003: // RSA-4096
		return 4 + 0x200 + 0x3C, nil
	case 0x10001, 0x10004: // RSA-2048
		return 4 + 0x100 + 0x3C, nil
	case 0x10002, 0x10005: // ECDSA
		return 4 + 0x3C + 0x40, nil
	}
	return 0, fmt.Errorf("unknown signature type %08X", sigType)
}

const (
	tmdHeaderSize   = 0xC4
	tmdInfoRecords  = 64 * 0x24
	tmdChunkSize    = 0x30
	metaSMDHOffset  = 0x400
	smdhSize        = 0x36C0
	smdhTitleSize   = 0x200
	smdhTitleCount  = 16
	smdhTitleOffset = 0x8
)

func (f *File) parseTMD(index []byte, contentOff int64, contentSize uint64) error {
	t := f.TMD
	if len(t) < 4 {
		return errors.New("tmd: too short")
	}
	sig, err := SignatureLen(binary.BigEndian.Uint32(t))
	if err != nil {
		return fmt.Errorf("tmd: %w", err)
	}
	if len(t) < sig+tmdHeaderSize {
		return errors.New("tmd: shorter than its header")
	}
	h := t[sig:]
	f.TitleID = binary.BigEndian.Uint64(h[0x4C:])
	f.TitleVersion = binary.BigEndian.Uint16(h[0x9C:])
	count := int(binary.BigEndian.Uint16(h[0x9E:]))

	chunks := sig + tmdHeaderSize + tmdInfoRecords
	if count > 0 && len(t) < chunks+count*tmdChunkSize {
		return fmt.Errorf("tmd: %d content records don't fit", count)
	}
	off := contentOff
	end := contentOff + int64(contentSize)
	for i := 0; i < count; i++ {
		c := t[chunks+i*tmdChunkSize:]
		ct := Content{
			ID:     binary.BigEndian.Uint32(c[0x0:]),
			Index:  binary.BigEndian.Uint16(c[0x4:]),
			Type:   binary.BigEndian.Uint16(c[0x6:]),
			Size:   binary.BigEndian.Uint64(c[0x8:]),
			Offset: -1,
		}
		copy(ct.Hash[:], c[0x10:0x30])
		if int(ct.Index/8) < len(index) && index[ct.Index/8]&(0x80>>(ct.Index%8)) != 0 {
			if ct.Size > uint64(end-off) {
				return fmt.Errorf("tmd: content %08x (%d bytes) runs past the content section", ct.ID, ct.Size)
			}
			ct.Offset = off
			off += int64(ct.Size)
		}
		f.Contents = append(f.Contents, ct)
	}
	return nil
}

// CDNTMD is the TMD as Nintendo's CDN serves it: the TMD followed by the CP and CA certificates that sign it.
// Those come from the CIA's cert chain (3dbrew "CDN": tmd = TMD + CP cert + CA cert).
func (f *File) CDNTMD() ([]byte, error) {
	certs, err := SplitCerts(f.Certs)
	if err != nil {
		return nil, err
	}
	var ca, cp []byte
	for _, c := range certs {
		switch {
		case len(c.Name) >= 2 && c.Name[:2] == "CA":
			ca = c.Raw
		case len(c.Name) >= 2 && c.Name[:2] == "CP":
			cp = c.Raw
		}
	}
	if ca == nil || cp == nil {
		return nil, errors.New("cert chain has no CA and CP certificates")
	}
	out := append([]byte{}, f.TMD...)
	out = append(out, cp...)
	return append(out, ca...), nil
}

// Cert is one certificate from a chain.
type Cert struct {
	Issuer, Name string
	Raw          []byte
}

// SplitCerts splits a concatenated certificate chain. Each cert: signature block, issuer (0x40), key type (u32),
// name (0x40), expiration (u32), then the public key, whose size depends on the key type.
func SplitCerts(b []byte) ([]Cert, error) {
	var out []Cert
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("cert: truncated")
		}
		sig, err := SignatureLen(binary.BigEndian.Uint32(b))
		if err != nil {
			return nil, fmt.Errorf("cert: %w", err)
		}
		if len(b) < sig+0x88 {
			return nil, errors.New("cert: truncated")
		}
		var key int
		switch binary.BigEndian.Uint32(b[sig+0x40:]) {
		case 0:
			key = 0x200 + 4 + 0x34 // RSA-4096
		case 1:
			key = 0x100 + 4 + 0x34 // RSA-2048
		case 2:
			key = 0x3C + 0x3C // ECC
		default:
			return nil, errors.New("cert: unknown key type")
		}
		n := sig + 0x88 + key
		if len(b) < n {
			return nil, errors.New("cert: truncated")
		}
		out = append(out, Cert{Issuer: cstr(b[sig : sig+0x40]), Name: cstr(b[sig+0x44 : sig+0x84]), Raw: b[:n:n]})
		b = b[n:]
	}
	return out, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// SMDH holds an application's names. Index Titles by language: 0 Japanese, 1 English, 2 French, 3 German,
// 4 Italian, 5 Spanish, 6 Simplified Chinese, 7 Korean, 8 Dutch, 9 Portuguese, 10 Russian, 11 Traditional Chinese.
type SMDH struct {
	Titles    [smdhTitleCount]AppTitle
	LargeIcon []byte // 48x48 RGB565, tiled
}

type AppTitle struct{ Short, Long, Publisher string }

// ParseSMDH reads an SMDH (magic "SMDH").
func ParseSMDH(b []byte) (*SMDH, error) {
	if len(b) < smdhSize || string(b[:4]) != "SMDH" {
		return nil, errors.New("not an SMDH")
	}
	s := &SMDH{LargeIcon: append([]byte{}, b[0x24C0:0x24C0+48*48*2]...)}
	for i := range s.Titles {
		t := b[smdhTitleOffset+i*smdhTitleSize:]
		s.Titles[i] = AppTitle{Short: utf16le(t[:0x80]), Long: utf16le(t[0x80:0x180]), Publisher: utf16le(t[0x180:0x200])}
	}
	return s, nil
}

// Title picks the first language in prefs with a name, then any language with one.
func (s *SMDH) Title(prefs ...int) AppTitle {
	for _, i := range prefs {
		if i >= 0 && i < len(s.Titles) && s.Titles[i].Short != "" {
			return s.Titles[i]
		}
	}
	for _, t := range s.Titles {
		if t.Short != "" {
			return t
		}
	}
	return AppTitle{}
}

func utf16le(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func align64(n uint64) uint64 { return (n + 63) &^ 63 }

// Icon decodes the large icon: 48x48 RGB565, stored as 8x8 tiles left to right, top to bottom, with the pixels in
// each tile in Z-order (3dbrew "SMDH", "Icon graphics"). Nil if the SMDH has no icon data.
func (s *SMDH) Icon() image.Image {
	const size = 48
	if len(s.LargeIcon) < size*size*2 {
		return nil
	}
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	i := 0
	for ty := 0; ty < size; ty += 8 {
		for tx := 0; tx < size; tx += 8 {
			for k := 0; k < 64; k++ {
				x := (k & 1) | (k>>1)&2 | (k>>2)&4
				y := (k>>1)&1 | (k>>2)&2 | (k>>3)&4
				v := binary.LittleEndian.Uint16(s.LargeIcon[i*2:])
				i++
				r, g, b := uint8(v>>11)&0x1F, uint8(v>>5)&0x3F, uint8(v)&0x1F
				img.Set(tx+x, ty+y, color.RGBA{r<<3 | r>>2, g<<2 | g>>4, b<<3 | b>>2, 0xFF})
			}
		}
	}
	return img
}

// ProductCode reads the product code ("CTR-P-AJRE") from the NCCH header of the first content. It's "" when that
// content is missing, encrypted with the title key, or not an NCCH.
func (f *File) ProductCode() string {
	for _, c := range f.Contents {
		if c.Index != 0 {
			continue
		}
		if !c.Present() || c.Encrypted() || c.Size < 0x200 {
			return ""
		}
		hdr := make([]byte, 0x160)
		if _, err := f.Reader(c).ReadAt(hdr, 0); err != nil || string(hdr[0x100:0x104]) != "NCCH" {
			return ""
		}
		return cstr(hdr[0x150:0x160])
	}
	return ""
}
