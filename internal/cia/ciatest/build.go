// Package ciatest builds small but well-formed CIAs for tests. Signatures and keys are zero-filled.
package ciatest

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

type Content struct {
	ID        uint32
	Index     uint16
	Encrypted bool
	Data      []byte
	Missing   bool // listed in the TMD but left out of the file
}

type Spec struct {
	TitleID  uint64
	Version  uint16
	Contents []Content
	Name     string // SMDH short title in English; empty means no meta section
	Long     string
	Author   string
}

// Build returns a CIA with a CA/XS/CP cert chain, an RSA-2048 ticket and TMD, the contents, and optional meta.
func Build(s Spec) []byte {
	certs := cat(cert(0x10003, "Root", 0, "CA00000003"), cert(0x10004, "Root-CA00000003", 1, "XS0000000c"),
		cert(0x10004, "Root-CA00000003", 1, "CP0000000b"))
	ticket := make([]byte, 4+0x100+0x3C+0x210)
	binary.BigEndian.PutUint32(ticket, 0x10004)

	tmd := make([]byte, 4+0x100+0x3C+0xC4+64*0x24+len(s.Contents)*0x30)
	binary.BigEndian.PutUint32(tmd, 0x10004)
	h := tmd[4+0x100+0x3C:]
	binary.BigEndian.PutUint64(h[0x4C:], s.TitleID)
	binary.BigEndian.PutUint16(h[0x9C:], s.Version)
	binary.BigEndian.PutUint16(h[0x9E:], uint16(len(s.Contents)))
	var index [0x2000]byte
	var data bytes.Buffer
	for i, c := range s.Contents {
		r := h[0xC4+64*0x24+i*0x30:]
		binary.BigEndian.PutUint32(r[0:], c.ID)
		binary.BigEndian.PutUint16(r[4:], c.Index)
		if c.Encrypted {
			binary.BigEndian.PutUint16(r[6:], 1)
		}
		binary.BigEndian.PutUint64(r[8:], uint64(len(c.Data)))
		if !c.Missing {
			index[c.Index/8] |= 0x80 >> (c.Index % 8)
			data.Write(c.Data)
		}
	}

	var meta []byte
	if s.Name != "" {
		meta = make([]byte, 0x400+0x36C0)
		smdh := meta[0x400:]
		copy(smdh, "SMDH")
		en := smdh[0x8+0x200:]
		putUTF16(en[:0x80], s.Name)
		putUTF16(en[0x80:0x180], s.Long)
		putUTF16(en[0x180:0x200], s.Author)
	}

	hdr := make([]byte, 0x2020)
	binary.LittleEndian.PutUint32(hdr[0x00:], 0x2020)
	binary.LittleEndian.PutUint32(hdr[0x08:], uint32(len(certs)))
	binary.LittleEndian.PutUint32(hdr[0x0C:], uint32(len(ticket)))
	binary.LittleEndian.PutUint32(hdr[0x10:], uint32(len(tmd)))
	binary.LittleEndian.PutUint32(hdr[0x14:], uint32(len(meta)))
	binary.LittleEndian.PutUint64(hdr[0x18:], uint64(data.Len()))
	copy(hdr[0x20:], index[:])

	var out bytes.Buffer
	for _, sec := range [][]byte{hdr, certs, ticket, tmd, data.Bytes(), meta} {
		out.Write(sec)
		for out.Len()%64 != 0 {
			out.WriteByte(0)
		}
	}
	return out.Bytes()
}

func cert(sigType uint32, issuer string, keyType uint32, name string) []byte {
	sig := map[uint32]int{0x10003: 4 + 0x200 + 0x3C, 0x10004: 4 + 0x100 + 0x3C}[sigType]
	key := map[uint32]int{0: 0x200 + 4 + 0x34, 1: 0x100 + 4 + 0x34}[keyType]
	b := make([]byte, sig+0x88+key)
	binary.BigEndian.PutUint32(b, sigType)
	copy(b[sig:], issuer)
	binary.BigEndian.PutUint32(b[sig+0x40:], keyType)
	copy(b[sig+0x44:], name)
	return b
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func putUTF16(dst []byte, s string) {
	for i, c := range utf16.Encode([]rune(s)) {
		if 2*i+1 >= len(dst) {
			break
		}
		binary.LittleEndian.PutUint16(dst[2*i:], c)
	}
}
