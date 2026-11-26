package dsi

import (
	"bytes"
	"math/big"
	"testing"
)

// Vectors from the Python reference (scratchpad ec/ref.py), which self-checks G on curve and n*G = O.
func TestSect233r1Vectors(t *testing.T) {
	if !generator().onCurve() {
		t.Fatal("G not on curve")
	}
	if !sectB.equal(mustGF("066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD")) {
		t.Fatal("b mismatch")
	}
	// n*G == O
	if !scalarMul(sectN, generator()).inf {
		t.Fatal("n*G != O")
	}
	// (n-1)*G == -G == (Gx, Gx+Gy)
	negG := scalarMul(new(big.Int).Sub(sectN, big.NewInt(1)), generator())
	if negG.inf || !negG.x.equal(sectGx) || !negG.y.equal(gfAdd(sectGx, sectGy)) {
		t.Fatal("(n-1)G != -G")
	}

	// Field mul and inverse vectors.
	if got := gfMul(sectGx, sectGy); !got.equal(mustGF("1c6d6a3072ecb17f328c969cb7d4fd91d3e8e5d7dba0c7eb352828319")) {
		t.Errorf("mul(Gx,Gy) = %x", got.bytes())
	}
	if got := gfInv(sectGx); !got.equal(mustGF("b8b6e54d512aed5603c814e5c97382778751a79bfa4a0ee8213d2f5b4")) {
		t.Errorf("inv(Gx) = %x", got.bytes())
	}
	if got := gfMul(sectGx, gfInv(sectGx)); !got.equal(gf{1, 0, 0, 0}) {
		t.Errorf("Gx * Gx^-1 = %x, want 1", got.bytes())
	}

	// Scalar-multiplication vectors k*G.
	for _, v := range []struct {
		k    int64
		x, y string
	}{
		{2, "845fd61638bac7d9e109a67a1f7047dc0fd9a5488a8468364bdc592aad", "1b1420774abba2587c83900984765a8a85d776325fc39cc7823d734660"},
		{3, "80f50a330911bd753a76364595b9f0158c4d02a85cc0e3fb6ea0aef9ff", "17a49033f12eb52675e98e6432cc27104bd5c42bcbe3daf76901c9b8743"},
		{7, "1f7d14c8236367ed87eb63873c754bd8b7ec794d966b02e26c932b29f9c", "8f7c01df764b179486cfc7b5658c1829baf50af0dd42e822556f72ceea"},
		{0x12345, "36e995d5b040ff03cf1ad342a1fe54ae1a55acac45157d4907be447e6d", "45e1dc273e41e3b93a4fd00dd7f564d7b0dbebf7c0e52a6b088fe6149c"},
	} {
		p := scalarMul(big.NewInt(v.k), generator())
		if p.inf || !p.x.equal(mustGF(v.x)) || !p.y.equal(mustGF(v.y)) {
			t.Errorf("%d*G = (%x, %x)", v.k, p.x.bytes(), p.y.bytes())
		}
		if !p.onCurve() {
			t.Errorf("%d*G not on curve", v.k)
		}
	}
}

func TestGenerateDeviceKey(t *testing.T) {
	for i := 0; i < 20; i++ {
		kp, err := GenerateDeviceKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(kp.Private) != 30 || len(kp.PublicX) != 30 || len(kp.PublicY) != 30 {
			t.Fatalf("lengths: %d %d %d", len(kp.Private), len(kp.PublicX), len(kp.PublicY))
		}
		// Q = d*G must be on the curve, and recomputing d*G must give the reported (X,Y).
		d := new(big.Int).SetBytes(kp.Private)
		q := scalarMul(d, generator())
		if q.inf || !bytes.Equal(q.x.bytes(), kp.PublicX) || !bytes.Equal(q.y.bytes(), kp.PublicY) {
			t.Fatal("public point doesn't match d*G")
		}
		p := point{x: gfFromBytes(kp.PublicX), y: gfFromBytes(kp.PublicY)}
		if !p.onCurve() {
			t.Fatal("public point not on curve")
		}
	}
}

func TestGFBytesRoundTrip(t *testing.T) {
	for _, g := range []gf{sectGx, sectGy, sectB, {1, 0, 0, 0}, {}} {
		if !gfFromBytes(g.bytes()).equal(g) {
			t.Errorf("round trip failed for %x", g.bytes())
		}
	}
}
