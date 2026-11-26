package dsi

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"time"
)

// The DSi's browser engine (the shop's pages) opens HTTPS with an SSLv2-format ClientHello offering TLS 1.0.
// Go's crypto/tls and current OpenSSL both refuse that format, so this is a minimal TLS 1.0 server for it:
// RSA key exchange only, AES-CBC or RC4 with HMAC-SHA1/MD5, no renegotiation or session resumption. It is
// for the shop on our own LAN and nothing else.

// Legacy TLS cipher suites we can serve, in our order of preference.
var legacySuites = []struct {
	id            uint16
	name          string
	keyLen, ivLen int
	mac           func() hash.Hash
	macLen        int
	rc4           bool
}{
	{0x002F, "AES128-SHA", 16, 16, sha1.New, 20, false},
	{0x0035, "AES256-SHA", 32, 16, sha1.New, 20, false},
	{0x0005, "RC4-SHA", 16, 0, sha1.New, 20, true},
	{0x0004, "RC4-MD5", 16, 0, md5.New, 16, true},
}

// LegacyInfo describes a finished legacy handshake, for the log.
type LegacyInfo struct {
	HelloFormat string // "sslv2" or "tls"
	Version     uint16 // what the client offered
	Cipher      string
	Offered     []uint16
}

// LegacyServer performs the handshake on conn, whose first bytes (the ClientHello) can be read from br.
func LegacyServer(conn net.Conn, br *bufio.Reader, cert *tls.Certificate) (net.Conn, *LegacyInfo, error) {
	c := &legacyConn{raw: conn, br: br}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})
	info, err := c.handshake(cert)
	if err != nil {
		return nil, info, err
	}
	return c, info, nil
}

type legacyConn struct {
	raw net.Conn
	br  *bufio.Reader

	transcript bytes.Buffer // handshake messages, for Finished

	in, out halfConn
	rmu     sync.Mutex
	wmu     sync.Mutex
	pending []byte // decrypted application data not yet read
	rerr    error
}

type halfConn struct {
	seq    uint64
	macKey []byte
	mac    func() hash.Hash
	macLen int
	cbc    cipher.Block
	iv     []byte
	rc4    *rc4.Cipher
	on     bool
}

const (
	recChangeCipherSpec = 20
	recAlert            = 21
	recHandshake        = 22
	recAppData          = 23
	tls10               = 0x0301
)

func (c *legacyConn) handshake(cert *tls.Certificate) (*LegacyInfo, error) {
	info := &LegacyInfo{}
	first, err := c.br.Peek(1)
	if err != nil {
		return info, err
	}
	var clientRandom []byte
	if first[0]&0x80 != 0 {
		info.HelloFormat = "sslv2"
		clientRandom, err = c.readV2Hello(info)
	} else {
		info.HelloFormat = "tls"
		clientRandom, err = c.readV3Hello(info)
	}
	if err != nil {
		return info, err
	}
	if info.Version < tls10 {
		return info, fmt.Errorf("client offers only version %#04x (SSL 3.0 isn't implemented)", info.Version)
	}
	suite := -1
	for i, s := range legacySuites {
		for _, id := range info.Offered {
			if id == s.id && suite < 0 {
				suite = i
			}
		}
	}
	if suite < 0 {
		return info, fmt.Errorf("no common cipher suite (client offers %04x)", info.Offered)
	}
	cs := legacySuites[suite]
	info.Cipher = cs.name

	// ServerHello, Certificate, ServerHelloDone
	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	binary.BigEndian.PutUint32(serverRandom, uint32(time.Now().Unix()))
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	var hello []byte
	hello = binary.BigEndian.AppendUint16(hello, tls10)
	hello = append(hello, serverRandom...)
	hello = append(hello, byte(len(sessionID)))
	hello = append(hello, sessionID...)
	hello = binary.BigEndian.AppendUint16(hello, cs.id)
	hello = append(hello, 0) // no compression
	for _, id := range info.Offered {
		if id == 0x00FF { // TLS_EMPTY_RENEGOTIATION_INFO_SCSV: answer with an empty renegotiation_info
			hello = append(hello, 0, 5, 0xFF, 0x01, 0, 1, 0)
		}
	}
	var certs []byte
	for _, der := range cert.Certificate {
		certs = append(certs, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		certs = append(certs, der...)
	}
	certMsg := append([]byte{byte(len(certs) >> 16), byte(len(certs) >> 8), byte(len(certs))}, certs...)
	var flight []byte
	flight = append(flight, c.hsMsg(2, hello)...)
	flight = append(flight, c.hsMsg(11, certMsg)...)
	flight = append(flight, c.hsMsg(14, nil)...)
	if err := c.writeRecord(recHandshake, flight); err != nil {
		return info, err
	}

	// ClientKeyExchange
	typ, body, raw, err := c.readHandshake()
	if err != nil {
		return info, err
	}
	if typ != 16 {
		return info, fmt.Errorf("expected ClientKeyExchange, got handshake type %d", typ)
	}
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return info, errors.New("certificate key isn't RSA")
	}
	enc := body
	if len(body) == 2+key.Size() && int(binary.BigEndian.Uint16(body)) == key.Size() {
		enc = body[2:]
	}
	pre := make([]byte, 48)
	rand.Read(pre) // on a bad decryption, carry on with random bytes and fail at Finished (Bleichenbacher)
	if err := rsa.DecryptPKCS1v15SessionKey(nil, key, enc, pre); err != nil {
		return info, fmt.Errorf("ClientKeyExchange: %w", err)
	}
	c.transcript.Write(raw)

	master := prf10(pre, "master secret", append(append([]byte(nil), clientRandom...), serverRandom...), 48)
	kb := prf10(master, "key expansion", append(append([]byte(nil), serverRandom...), clientRandom...), 2*cs.macLen+2*cs.keyLen+2*cs.ivLen)
	cMac, kb := kb[:cs.macLen], kb[cs.macLen:]
	sMac, kb := kb[:cs.macLen], kb[cs.macLen:]
	cKey, kb := kb[:cs.keyLen], kb[cs.keyLen:]
	sKey, kb := kb[:cs.keyLen], kb[cs.keyLen:]
	cIV, sIV := kb[:cs.ivLen], kb[cs.ivLen:2*cs.ivLen]

	// ChangeCipherSpec, then the client's Finished under the new keys.
	rtyp, rbody, err := c.readRecord()
	if err != nil {
		return info, err
	}
	if rtyp != recChangeCipherSpec || !bytes.Equal(rbody, []byte{1}) {
		return info, fmt.Errorf("expected ChangeCipherSpec, got record type %d", rtyp)
	}
	if err := c.in.setup(cs.rc4, cKey, cIV, cMac, cs.mac, cs.macLen); err != nil {
		return info, err
	}
	want := prf10(master, "client finished", c.transcriptHash(), 12)
	typ, body, raw, err = c.readHandshake()
	if err != nil {
		return info, err
	}
	if typ != 20 || subtle.ConstantTimeCompare(body, want) != 1 {
		return info, errors.New("client Finished doesn't verify")
	}
	c.transcript.Write(raw)

	if err := c.writeRecord(recChangeCipherSpec, []byte{1}); err != nil {
		return info, err
	}
	if err := c.out.setup(cs.rc4, sKey, sIV, sMac, cs.mac, cs.macLen); err != nil {
		return info, err
	}
	fin := c.hsMsg(20, prf10(master, "server finished", c.transcriptHash(), 12))
	return info, c.writeRecord(recHandshake, fin)
}

// readV2Hello parses an SSLv2-format CLIENT-HELLO. Its message bytes (without the 2-byte length) start
// the transcript, and the challenge, right-aligned in 32 bytes, is the client random.
func (c *legacyConn) readV2Hello(info *LegacyInfo) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return nil, err
	}
	n := int(h[0]&0x7F)<<8 | int(h[1])
	if n < 9 || n > 1024 {
		return nil, fmt.Errorf("SSLv2 hello length %d", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(c.br, msg); err != nil {
		return nil, err
	}
	if msg[0] != 1 {
		return nil, fmt.Errorf("SSLv2 message type %d isn't CLIENT-HELLO", msg[0])
	}
	info.Version = binary.BigEndian.Uint16(msg[1:])
	csLen, sidLen, chLen := int(binary.BigEndian.Uint16(msg[3:])), int(binary.BigEndian.Uint16(msg[5:])), int(binary.BigEndian.Uint16(msg[7:]))
	if 9+csLen+sidLen+chLen != n || csLen%3 != 0 || chLen < 16 || chLen > 32 {
		return nil, errors.New("malformed SSLv2 CLIENT-HELLO")
	}
	specs := msg[9 : 9+csLen]
	for i := 0; i < len(specs); i += 3 {
		if specs[i] == 0 { // SSLv3/TLS suites are 00 xx yy; others are SSLv2-only
			info.Offered = append(info.Offered, binary.BigEndian.Uint16(specs[i+1:]))
		}
	}
	challenge := msg[9+csLen+sidLen:]
	random := make([]byte, 32)
	copy(random[32-len(challenge):], challenge)
	c.transcript.Write(msg)
	return random, nil
}

// readV3Hello parses an ordinary ClientHello (only used by tests: production sends these to crypto/tls).
func (c *legacyConn) readV3Hello(info *LegacyInfo) ([]byte, error) {
	typ, body, raw, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	if typ != 1 || len(body) < 35 {
		return nil, errors.New("expected ClientHello")
	}
	info.Version = binary.BigEndian.Uint16(body)
	random := append([]byte(nil), body[2:34]...)
	p := 34 + 1 + int(body[34])
	if p+2 > len(body) {
		return nil, errors.New("short ClientHello")
	}
	n := int(binary.BigEndian.Uint16(body[p:]))
	if p+2+n > len(body) {
		return nil, errors.New("short ClientHello")
	}
	for i := p + 2; i+1 < p+2+n; i += 2 {
		info.Offered = append(info.Offered, binary.BigEndian.Uint16(body[i:]))
	}
	c.transcript.Write(raw)
	return random, nil
}

func (c *legacyConn) hsMsg(typ byte, body []byte) []byte {
	m := append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	c.transcript.Write(m)
	return m
}

func (c *legacyConn) transcriptHash() []byte {
	m, s := md5.Sum(c.transcript.Bytes()), sha1.Sum(c.transcript.Bytes())
	return append(m[:], s[:]...)
}

var errAlert = errors.New("peer sent an alert")

func (c *legacyConn) readHandshake() (typ byte, body, raw []byte, err error) {
	for len(c.pending) < 4 || len(c.pending) < 4+int(c.pending[1])<<16|int(c.pending[2])<<8|int(c.pending[3]) {
		rtyp, rbody, err := c.readRecord()
		if err != nil {
			return 0, nil, nil, err
		}
		if rtyp == recAlert {
			return 0, nil, nil, fmt.Errorf("%w %x during handshake", errAlert, rbody)
		}
		if rtyp != recHandshake {
			return 0, nil, nil, fmt.Errorf("expected handshake record, got type %d", rtyp)
		}
		c.pending = append(c.pending, rbody...)
	}
	n := 4 + (int(c.pending[1])<<16 | int(c.pending[2])<<8 | int(c.pending[3]))
	raw = append([]byte(nil), c.pending[:n]...)
	c.pending = c.pending[n:]
	return raw[0], raw[4:], raw, nil
}

func (c *legacyConn) readRecord() (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(h[3:]))
	if n > 16384+2048 {
		return 0, nil, fmt.Errorf("record too long (%d)", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(c.br, data); err != nil {
		return 0, nil, err
	}
	if !c.in.on {
		return h[0], data, nil
	}
	plain, err := c.in.open(h[0], data)
	return h[0], plain, err
}

func (c *legacyConn) writeRecord(typ byte, data []byte) error {
	for first := true; first || len(data) > 0; first = false {
		chunk := data
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		data = data[len(chunk):]
		payload := chunk
		if c.out.on {
			payload = c.out.seal(typ, chunk)
		}
		rec := append([]byte{typ, tls10 >> 8, tls10 & 0xFF, byte(len(payload) >> 8), byte(len(payload))}, payload...)
		if _, err := c.raw.Write(rec); err != nil {
			return err
		}
	}
	return nil
}

func (h *halfConn) setup(isRC4 bool, key, iv, macKey []byte, mac func() hash.Hash, macLen int) error {
	h.macKey, h.mac, h.macLen, h.seq, h.on = macKey, mac, macLen, 0, true
	if isRC4 {
		var err error
		h.rc4, err = rc4.NewCipher(key)
		return err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	h.cbc, h.iv = b, append([]byte(nil), iv...)
	return nil
}

func (h *halfConn) macOf(typ byte, data []byte) []byte {
	m := hmac.New(h.mac, h.macKey)
	var hdr [13]byte
	binary.BigEndian.PutUint64(hdr[:], h.seq)
	hdr[8], hdr[9], hdr[10] = typ, tls10>>8, tls10&0xFF
	binary.BigEndian.PutUint16(hdr[11:], uint16(len(data)))
	m.Write(hdr[:])
	m.Write(data)
	return m.Sum(nil)
}

func (h *halfConn) seal(typ byte, data []byte) []byte {
	out := append(append([]byte(nil), data...), h.macOf(typ, data)...)
	h.seq++
	if h.rc4 != nil {
		h.rc4.XORKeyStream(out, out)
		return out
	}
	pad := aes.BlockSize - (len(out)+1)%aes.BlockSize
	if pad == aes.BlockSize {
		pad = 0
	}
	for i := 0; i <= pad; i++ {
		out = append(out, byte(pad))
	}
	cipher.NewCBCEncrypter(h.cbc, h.iv).CryptBlocks(out, out)
	h.iv = append([]byte(nil), out[len(out)-aes.BlockSize:]...) // TLS 1.0: the last block is the next IV
	return out
}

var errBadRecordMAC = errors.New("bad record MAC")

func (h *halfConn) open(typ byte, data []byte) ([]byte, error) {
	buf := append([]byte(nil), data...)
	if h.rc4 != nil {
		h.rc4.XORKeyStream(buf, buf)
	} else {
		if len(buf) == 0 || len(buf)%aes.BlockSize != 0 {
			return nil, errBadRecordMAC
		}
		next := append([]byte(nil), buf[len(buf)-aes.BlockSize:]...)
		cipher.NewCBCDecrypter(h.cbc, h.iv).CryptBlocks(buf, buf)
		h.iv = next
		pad := int(buf[len(buf)-1])
		if pad+1 > len(buf) {
			return nil, errBadRecordMAC
		}
		buf = buf[:len(buf)-pad-1]
	}
	if len(buf) < h.macLen {
		return nil, errBadRecordMAC
	}
	data, mac := buf[:len(buf)-h.macLen], buf[len(buf)-h.macLen:]
	if !hmac.Equal(mac, h.macOf(typ, data)) {
		return nil, errBadRecordMAC
	}
	h.seq++
	return data, nil
}

// prf10 is the TLS 1.0 PRF: P_MD5 over the first half of the secret XOR P_SHA1 over the second half.
func prf10(secret []byte, label string, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	s1, s2 := secret[:half], secret[len(secret)-half:]
	ls := append([]byte(label), seed...)
	a, b := pHash(md5.New, s1, ls, n), pHash(sha1.New, s2, ls, n)
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	var out []byte
	a := seed
	for len(out) < n {
		m := hmac.New(h, secret)
		m.Write(a)
		a = m.Sum(nil)
		m = hmac.New(h, secret)
		m.Write(a)
		m.Write(seed)
		out = append(out, m.Sum(nil)...)
	}
	return out[:n]
}

// net.Conn

func (c *legacyConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		typ, data, err := c.readRecord()
		switch {
		case err != nil:
			c.rerr = err
		case typ == recAlert:
			c.rerr = io.EOF // close_notify or a fatal alert: either way, we're done
		case typ == recAppData:
			c.pending = data
		case typ == recHandshake:
			c.rerr = errors.New("renegotiation isn't supported")
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *legacyConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.writeRecord(recAppData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *legacyConn) Close() error {
	c.wmu.Lock()
	if c.out.on {
		c.writeRecord(recAlert, []byte{1, 0}) // close_notify
	}
	c.wmu.Unlock()
	return c.raw.Close()
}

func (c *legacyConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *legacyConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *legacyConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *legacyConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *legacyConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
