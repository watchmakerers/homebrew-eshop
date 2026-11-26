package dsi

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
)

func testServer(t *testing.T) (addr string, ca *CA) {
	t.Helper()
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{Listener: ln, ForceLegacy: true,
		Cert: func(string) (*tls.Certificate, error) { return ca.Leaf(PagesHost) },
		Log: func(_ string, info *LegacyInfo, err error) {
			if err != nil {
				t.Logf("legacy handshake: %+v: %v", info, err)
			}
		}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello "+r.URL.Path+" "+strings.Repeat("x", 40000)) // > one record
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), ca
}

// TestLegacyTLSWithOpenSSL checks the handshake, key derivation and record layer against an independent
// implementation: OpenSSL's TLS 1.0 client (with an ordinary hello; the SSLv2 hello is tested below).
func TestLegacyTLSWithOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl")
	}
	addr, ca := testServer(t)
	caFile := t.TempDir() + "/ca.pem"
	cmd := exec.Command("openssl", "x509", "-inform", "DER", "-out", caFile)
	cmd.Stdin = bytes.NewReader(ca.Cert.Raw)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl x509: %v %s", err, out)
	}
	for _, suite := range []string{"AES128-SHA", "AES256-SHA"} {
		t.Run(suite, func(t *testing.T) {
			c := exec.Command("openssl", "s_client", "-connect", addr, "-tls1", "-cipher", suite+":@SECLEVEL=0",
				"-CAfile", caFile, "-verify_return_error", "-quiet", "-noservername")
			c.Stdin = strings.NewReader("GET /index_u HTTP/1.1\r\nHost: " + PagesHost + "\r\nConnection: close\r\n\r\n")
			out, err := c.CombinedOutput()
			if err != nil || !bytes.Contains(out, []byte("hello /index_u xxxx")) || bytes.Count(out, []byte("x")) < 40000 {
				t.Fatalf("%v\n%.600s", err, out)
			}
		})
	}
}

// TestSSLv2Hello drives a handshake that starts with an SSLv2-format CLIENT-HELLO, using this package's
// own primitives for the client side (OpenSSL can no longer send one).
func TestSSLv2Hello(t *testing.T) {
	addr, ca := testServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl := &legacyConn{raw: conn}
	cl.br = newReader(conn)

	challenge := bytes.Repeat([]byte{0xAB}, 16)
	specs := []byte{0, 0, 0x2F, 0, 0, 0x05, 0x07, 0x00, 0xC0} // AES128-SHA, RC4-SHA, an SSLv2-only suite
	msg := append([]byte{1, 0x03, 0x01, 0, byte(len(specs)), 0, 0, 0, byte(len(challenge))}, specs...)
	msg = append(msg, challenge...)
	conn.Write(append([]byte{0x80, byte(len(msg))}, msg...))
	cl.transcript.Write(msg)
	clientRandom := append(make([]byte, 16), challenge...)

	// ServerHello, Certificate, ServerHelloDone
	typ, body, raw, err := cl.readHandshake()
	if err != nil || typ != 2 {
		t.Fatalf("ServerHello: %d %v", typ, err)
	}
	cl.transcript.Write(raw)
	serverRandom := body[2:34]
	if suite := body[35+int(body[34]):]; suite[0] != 0 || suite[1] != 0x2F {
		t.Fatalf("suite %x", suite[:2])
	}
	for _, want := range []byte{11, 14} {
		typ, _, raw, err := cl.readHandshake()
		if err != nil || typ != want {
			t.Fatalf("want %d got %d %v", want, typ, err)
		}
		cl.transcript.Write(raw)
	}

	leaf, _ := ca.Leaf(PagesHost)
	pre := append([]byte{3, 1}, bytes.Repeat([]byte{7}, 46)...)
	encPre, err := rsaEncrypt(leaf, pre)
	if err != nil {
		t.Fatal(err)
	}
	cke := append([]byte{byte(len(encPre) >> 8), byte(len(encPre))}, encPre...)
	cl.writeRecord(recHandshake, cl.hsMsg(16, cke))

	master := prf10(pre, "master secret", append(append([]byte(nil), clientRandom...), serverRandom...), 48)
	kb := prf10(master, "key expansion", append(append([]byte(nil), serverRandom...), clientRandom...), 2*20+2*16+2*16)
	cMac, sMac, cKey, sKey, cIV, sIV := kb[0:20], kb[20:40], kb[40:56], kb[56:72], kb[72:88], kb[88:104]
	cl.writeRecord(recChangeCipherSpec, []byte{1})
	cl.out.setup(false, cKey, cIV, cMac, legacySuites[0].mac, 20)
	cl.writeRecord(recHandshake, cl.hsMsg(20, prf10(master, "client finished", cl.transcriptHash(), 12)))

	if typ, _, err := cl.readRecord(); err != nil || typ != recChangeCipherSpec {
		t.Fatalf("server CCS: %d %v", typ, err)
	}
	cl.in.setup(false, sKey, sIV, sMac, legacySuites[0].mac, 20)
	want := prf10(master, "server finished", cl.transcriptHash(), 12)
	typ, body, _, err = cl.readHandshake()
	if err != nil || typ != 20 || !bytes.Equal(body, want) {
		t.Fatalf("server Finished: %d %v", typ, err)
	}

	cl.Write([]byte("GET /v2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	resp, _ := io.ReadAll(cl)
	if !bytes.Contains(resp, []byte("hello /v2 xxxx")) {
		t.Fatalf("response: %.300q", resp)
	}
}

func newReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

func rsaEncrypt(cert *tls.Certificate, msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &cert.PrivateKey.(*rsa.PrivateKey).PublicKey, msg)
}
