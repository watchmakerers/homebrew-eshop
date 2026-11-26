package dsi

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

// sect233r1 (NIST B-233): the binary-field elliptic curve the DSi uses for its device keys. Go's standard
// library has no binary-field curves, so this implements the minimum needed to mint a device key pair: field
// arithmetic over GF(2^233) (reduction f(x) = x^233 + x^74 + 1), curve point operations, and scalar
// multiplication. The server generates (private scalar d, public point Q = d*G); the console signs with d.
//
// Curve: y^2 + x*y = x^3 + a*x^2 + b, a = 1. Field elements are 30-byte big-endian (233 bits, top bits 0).

// gf is a GF(2^233) element: 4 little-endian 64-bit words (bits 0..63 in w[0]); bits 233..255 are always 0.
type gf [4]uint64

// Curve order n and base point G, from SEC 2. b is the curve coefficient.
var (
	sectN  = mustBig("1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7")
	sectB  = mustGF("066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD")
	sectGx = mustGF("0FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B")
	sectGy = mustGF("1006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052")
)

func mustBig(hexStr string) *big.Int {
	n, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("sect233r1: bad bigint " + hexStr)
	}
	return n
}

func mustGF(hexStr string) gf {
	n := mustBig(hexStr)
	var g gf
	for i := 0; i < 4; i++ {
		g[i] = n.Uint64() & 0xFFFFFFFFFFFFFFFF
		n = new(big.Int).Rsh(n, 64)
	}
	return g
}

func (g gf) isZero() bool { return g[0]|g[1]|g[2]|g[3] == 0 }

func (g gf) equal(h gf) bool { return g[0] == h[0] && g[1] == h[1] && g[2] == h[2] && g[3] == h[3] }

func gfAdd(a, b gf) gf { // addition in GF(2^m) is XOR
	return gf{a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]}
}

// clmul64 is a 64x64 -> 128 carry-less (GF(2)) multiply.
func clmul64(x, y uint64) (hi, lo uint64) {
	for i := 0; i < 64; i++ {
		if (y>>uint(i))&1 == 1 {
			lo ^= x << uint(i)
			if i != 0 {
				hi ^= x >> uint(64-i)
			}
		}
	}
	return hi, lo
}

// gfMul multiplies two field elements (schoolbook carry-less, then reduce).
func gfMul(a, b gf) gf {
	var p [8]uint64
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			hi, lo := clmul64(a[i], b[j])
			p[i+j] ^= lo
			p[i+j+1] ^= hi
		}
	}
	return gfReduce(p)
}

func gfSqr(a gf) gf { return gfMul(a, a) }

// gfReduce reduces a 512-bit product modulo f(x) = x^233 + x^74 + 1. For every set bit at position
// p >= 233, x^p = x^(p-159) + x^(p-233). Folding downward from the top settles all overflow.
func gfReduce(p [8]uint64) gf {
	get := func(i int) uint64 { return (p[i>>6] >> uint(i&63)) & 1 }
	flip := func(i int) { p[i>>6] ^= 1 << uint(i&63) }
	for bit := 465; bit >= 233; bit-- {
		if get(bit) == 1 {
			flip(bit)
			flip(bit - 159) // + x^74 term  (p-233+74)
			flip(bit - 233) // + 1 term
		}
	}
	return gf{p[0], p[1], p[2], p[3]}
}

// gfInv computes a^-1 via Fermat: a^(2^233-2) = product_{i=1..232} a^(2^i).
func gfInv(a gf) gf {
	t := a
	acc := gf{1, 0, 0, 0}
	for i := 1; i < 233; i++ {
		t = gfSqr(t)
		acc = gfMul(acc, t)
	}
	return acc
}

// point is an affine curve point; inf marks the point at infinity.
type point struct {
	x, y gf
	inf  bool
}

func (p point) onCurve() bool {
	if p.inf {
		return true
	}
	// y^2 + x*y == x^3 + x^2 + b   (a = 1)
	lhs := gfAdd(gfSqr(p.y), gfMul(p.x, p.y))
	x2 := gfSqr(p.x)
	rhs := gfAdd(gfAdd(gfMul(x2, p.x), x2), sectB)
	return lhs.equal(rhs)
}

func ptDouble(p point) point {
	if p.inf || p.x.isZero() {
		return point{inf: true}
	}
	// l = x + y/x ; x3 = l^2 + l + a ; y3 = x^2 + (l+1)*x3
	l := gfAdd(p.x, gfMul(p.y, gfInv(p.x)))
	x3 := gfAdd(gfAdd(gfSqr(l), l), gf{1, 0, 0, 0})
	y3 := gfAdd(gfSqr(p.x), gfMul(gfAdd(l, gf{1, 0, 0, 0}), x3))
	return point{x: x3, y: y3}
}

func ptAdd(p, q point) point {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	if p.x.equal(q.x) {
		if p.y.equal(q.y) {
			return ptDouble(p)
		}
		return point{inf: true} // p == -q
	}
	// l = (y1+y2)/(x1+x2) ; x3 = l^2 + l + x1 + x2 + a ; y3 = l*(x1+x3) + x3 + y1
	l := gfMul(gfAdd(p.y, q.y), gfInv(gfAdd(p.x, q.x)))
	x3 := gfAdd(gfAdd(gfAdd(gfSqr(l), l), gfAdd(p.x, q.x)), gf{1, 0, 0, 0})
	y3 := gfAdd(gfAdd(gfMul(l, gfAdd(p.x, x3)), x3), p.y)
	return point{x: x3, y: y3}
}

func scalarMul(k *big.Int, p point) point {
	r := point{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = ptDouble(r)
		if k.Bit(i) == 1 {
			r = ptAdd(r, p)
		}
	}
	return r
}

// generator returns G.
func generator() point { return point{x: sectGx, y: sectGy} }

// gf <-> 30-byte big-endian conversion (field element as stored in a cert).

func (g gf) bytes() []byte {
	out := make([]byte, 30) // 233 bits -> 30 bytes, big-endian
	for i := 0; i < 4; i++ {
		w := g[i]
		for j := 0; j < 8; j++ {
			pos := i*8 + j // byte index from the little end
			if pos < 30 {
				out[30-1-pos] = byte(w >> uint(8*j))
			}
		}
	}
	return out
}

func gfFromBytes(b []byte) gf {
	var g gf
	for pos := 0; pos < len(b) && pos < 30; pos++ {
		v := b[len(b)-1-pos]
		g[pos>>3] |= uint64(v) << uint(8*(pos&7))
	}
	return g
}

// DeviceKeyPair is a freshly minted sect233r1 key pair for a DSi device certificate.
type DeviceKeyPair struct {
	Private []byte // 30-byte big-endian scalar d (stored in dev.kp / returned as DeviceKey)
	PublicX []byte // 30-byte big-endian point X
	PublicY []byte // 30-byte big-endian point Y
}

// GenerateDeviceKey picks a random private scalar d in [1, n-1] and returns it with Q = d*G.
func GenerateDeviceKey(randr io.Reader) (*DeviceKeyPair, error) {
	if randr == nil {
		randr = rand.Reader
	}
	// d in [1, n-1]
	max := new(big.Int).Sub(sectN, big.NewInt(1))
	d, err := rand.Int(randr, max)
	if err != nil {
		return nil, err
	}
	d.Add(d, big.NewInt(1))
	q := scalarMul(d, generator())
	if q.inf {
		return nil, errors.New("sect233r1: d*G is infinity")
	}
	priv := make([]byte, 30)
	d.FillBytes(priv)
	return &DeviceKeyPair{Private: priv, PublicX: q.x.bytes(), PublicY: q.y.bytes()}, nil
}
