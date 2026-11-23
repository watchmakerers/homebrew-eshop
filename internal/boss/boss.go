// Package boss reads and writes 3DS SpotPass (BOSS) files: the container a BOSS task downloads, which the
// console's BOSS module decrypts and checks before handing the payload to the app.
//
// Layout (as Pretendo's boss-crypto implements it, src/3ds.ts; all big-endian):
//
//	0x00  "boss", u32 0x10001, u32 file size, u64 serial, u16 1, u16 pad, u16 hash type 2 (SHA-256),
//	      u16 RSA type 2 (RSA-2048), 12-byte IV                                       (0x28, plaintext)
//	0x28  content header: flags (0x80), 15 zero bytes, u16 payload count, SHA-256, RSA signature  (0x132)
//	0x15A payload header: u64 program ID, u32 0, u32 data type, u32 size, u32 NS data ID, u32 version,
//	      SHA-256, RSA signature                                                      (0x13C)
//	0x296 payload
//
// Everything from 0x28 on is AES-128-CTR with the console's BOSS key (keyslot 0x38's normal key), counter =
// IV || 00000001. The content header hash is SHA-256 of its first 0x12 bytes followed by two zero bytes; the
// payload header hash is SHA-256 of its first 0x1C bytes, two zero bytes, and the payload. Signatures are left
// zero: they can't be made without Nintendo's key.
//
// The key is never part of this repository: callers read it from a file the user dumped from their own console.
package boss

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	headerSize        = 0x28
	contentHeaderSize = 0x132
	payloadHeaderSize = 0x13C
)

// Payload is one file inside a BOSS container.
type Payload struct {
	ProgramID uint64 // the title the data is for
	DataType  uint32
	NsDataID  uint32 // the ID the app looks the data up by
	Version   uint32
	Data      []byte
}

// File is a decoded container.
type File struct {
	Serial  uint64 // "release date" in some docs; a number that changes with each new file
	Payload Payload
}

// LoadKey reads a 16-byte key from a file holding 32 hex digits (whitespace ignored) or the raw 16 bytes.
func LoadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 16 {
		return b, nil
	}
	k, err := hex.DecodeString(strings.Join(strings.Fields(string(b)), ""))
	if err != nil || len(k) != 16 {
		return nil, fmt.Errorf("%s: want 32 hex digits or 16 raw bytes", path)
	}
	return k, nil
}

func ctr(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	counter := make([]byte, 16)
	copy(counter, iv)
	counter[15] = 1
	return cipher.NewCTR(block, counter), nil
}

// Seal builds an encrypted container holding one payload.
func Seal(key []byte, f File) ([]byte, error) {
	p := f.Payload
	body := make([]byte, contentHeaderSize+payloadHeaderSize+len(p.Data))

	ch := body[:contentHeaderSize]
	ch[0] = 0x80
	binary.BigEndian.PutUint16(ch[0x10:], 1)
	sum := sha256.Sum256(append(append([]byte{}, ch[:0x12]...), 0, 0))
	copy(ch[0x12:], sum[:])

	ph := body[contentHeaderSize : contentHeaderSize+payloadHeaderSize]
	binary.BigEndian.PutUint64(ph[0x00:], p.ProgramID)
	binary.BigEndian.PutUint32(ph[0x0C:], p.DataType)
	binary.BigEndian.PutUint32(ph[0x10:], uint32(len(p.Data)))
	binary.BigEndian.PutUint32(ph[0x14:], p.NsDataID)
	binary.BigEndian.PutUint32(ph[0x18:], p.Version)
	copy(body[contentHeaderSize+payloadHeaderSize:], p.Data)
	h := sha256.New()
	h.Write(ph[:0x1C])
	h.Write([]byte{0, 0})
	h.Write(p.Data)
	copy(ph[0x1C:], h.Sum(nil))

	out := make([]byte, headerSize, headerSize+len(body))
	copy(out, "boss")
	binary.BigEndian.PutUint32(out[0x04:], 0x10001)
	binary.BigEndian.PutUint32(out[0x08:], uint32(headerSize+len(body)))
	binary.BigEndian.PutUint64(out[0x0C:], f.Serial)
	binary.BigEndian.PutUint16(out[0x14:], 1)
	binary.BigEndian.PutUint16(out[0x18:], 2)
	binary.BigEndian.PutUint16(out[0x1A:], 2)
	if _, err := rand.Read(out[0x1C:0x28]); err != nil {
		return nil, err
	}
	s, err := ctr(key, out[0x1C:0x28])
	if err != nil {
		return nil, err
	}
	enc := make([]byte, len(body))
	s.XORKeyStream(enc, body)
	return append(out, enc...), nil
}

// Open decrypts a container and checks both hashes, so a wrong key is reported as such.
func Open(key, b []byte) (*File, error) {
	if len(b) < headerSize+contentHeaderSize+payloadHeaderSize || string(b[:4]) != "boss" {
		return nil, errors.New("not a 3DS BOSS file")
	}
	if binary.BigEndian.Uint32(b[0x04:]) != 0x10001 || binary.BigEndian.Uint16(b[0x18:]) != 2 {
		return nil, errors.New("unsupported BOSS header")
	}
	if int(binary.BigEndian.Uint32(b[0x08:])) != len(b) {
		return nil, errors.New("BOSS file size doesn't match its header")
	}
	s, err := ctr(key, b[0x1C:0x28])
	if err != nil {
		return nil, err
	}
	body := make([]byte, len(b)-headerSize)
	s.XORKeyStream(body, b[headerSize:])

	ch := body[:contentHeaderSize]
	sum := sha256.Sum256(append(append([]byte{}, ch[:0x12]...), 0, 0))
	if !bytes.Equal(sum[:], ch[0x12:0x32]) {
		return nil, errors.New("content header hash mismatch (wrong key?)")
	}
	if n := binary.BigEndian.Uint16(ch[0x10:]); n != 1 {
		return nil, fmt.Errorf("%d payloads; only single-payload files are supported", n)
	}
	ph := body[contentHeaderSize : contentHeaderSize+payloadHeaderSize]
	size := int(binary.BigEndian.Uint32(ph[0x10:]))
	rest := body[contentHeaderSize+payloadHeaderSize:]
	if size > len(rest) {
		return nil, errors.New("payload runs past the end of the file")
	}
	data := rest[:size]
	h := sha256.New()
	h.Write(ph[:0x1C])
	h.Write([]byte{0, 0})
	h.Write(data)
	if !bytes.Equal(h.Sum(nil), ph[0x1C:0x3C]) {
		return nil, errors.New("payload hash mismatch")
	}
	return &File{
		Serial: binary.BigEndian.Uint64(b[0x0C:]),
		Payload: Payload{
			ProgramID: binary.BigEndian.Uint64(ph[0x00:]),
			DataType:  binary.BigEndian.Uint32(ph[0x0C:]),
			NsDataID:  binary.BigEndian.Uint32(ph[0x14:]),
			Version:   binary.BigEndian.Uint32(ph[0x18:]),
			Data:      append([]byte(nil), data...),
		},
	}, nil
}
