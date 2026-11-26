// Package dsi serves the Nintendo DSi Shop app (title 00030015484E46xx) from this PC: our own certificate
// authority, the patch that makes the shop trust it, and the services the shop talks to.
package dsi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The DSi's 2009 SSL library only knows SHA-1/MD5 signatures, and its built-in CA table holds 1024-bit keys,
// so the CA and every server certificate are RSA-1024 signed with SHA-1. They are only ever trusted by a DSi
// whose shop app we patched; nothing else should be pointed at them.
const keyBits = 1024

// CA is the certificate authority the patched shop trusts.
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey

	dir    string
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreateCA loads dir/ca.der + dir/ca.key, creating them if neither exists.
func LoadOrCreateCA(dir string) (*CA, error) {
	certFile, keyFile := filepath.Join(dir, "ca.der"), filepath.Join(dir, "ca.key")
	der, certErr := os.ReadFile(certFile)
	keyPEM, keyErr := os.ReadFile(keyFile)
	switch {
	case certErr == nil && keyErr == nil:
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", certFile, err)
		}
		block, _ := pem.Decode(keyPEM)
		if block == nil {
			return nil, fmt.Errorf("%s: not PEM", keyFile)
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keyFile, err)
		}
		return &CA{Cert: cert, Key: key, dir: dir, leaves: map[string]*tls.Certificate{}}, nil
	case !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("only one of %s and %s exists; delete it or supply both", certFile, keyFile)
	}

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		// Kept short: the patch writes this name into the shop's CA table in place of a 78-byte one.
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"homebrew-eshop"}, CommonName: "homebrew-eshop DSi CA"},
		NotBefore:             time.Date(2008, 1, 1, 0, 0, 0, 0, time.UTC), // the DSi clock may be anywhere
		NotAfter:              time.Date(2049, 12, 31, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certFile, der, 0o644); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, dir: dir, leaves: map[string]*tls.Certificate{}}, nil
}

// DNString is the CA's subject the way the DSi's built-in CA table spells names: the attribute values in
// certificate order, joined by ", " (e.g. "US, Washington, Nintendo of America Inc, NOA, Nintendo CA, ...").
func (ca *CA) DNString() (string, error) {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(ca.Cert.RawSubject, &rdns); err != nil {
		return "", err
	}
	var vals []string
	for _, set := range rdns {
		for _, atv := range set {
			vals = append(vals, fmt.Sprint(atv.Value))
		}
	}
	return strings.Join(vals, ", "), nil
}

// Modulus is the CA public key's modulus, big-endian, padded to keyBits/8 bytes.
func (ca *CA) Modulus() []byte {
	m := ca.Key.PublicKey.N.Bytes()
	out := make([]byte, keyBits/8)
	copy(out[len(out)-len(m):], m)
	return out
}

// ShopSANs returns the DNS names a shop server certificate should cover: the specific host plus every
// Nintendo shop/WFC hostname and matching wildcards, so one cert validates against any of them (the DSi
// sends no SNI, so we can't choose per connection).
func ShopSANs(host string) []string {
	// Explicit hostnames only: the DSi's 2009 SSL library rejects a certificate whose SAN list contains
	// wildcard (*.) entries (it answered 022e / certificate_unknown even for a host that worked before).
	names := []string{
		host,
		"nas.nintendowifi.net", "conntest.nintendowifi.net",
		"tss.t.shop.nintendowifi.net",
		"ias.t.shop.nintendowifi.net", "ecs.t.shop.nintendowifi.net",
		"cas.t.shop.nintendowifi.net", "ccs.t.shop.nintendowifi.net", "ucs.t.shop.nintendowifi.net",
		"tss.shop.nintendowifi.net", "ias.shop.nintendowifi.net", "ecs.shop.nintendowifi.net",
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// Leaf returns a server certificate for host signed by the CA, creating and caching it (in memory and as
// dir/leaf/<host>.der + .key) on first use. The cert covers every shop hostname (see ShopSANs).
func (ca *CA) Leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c := ca.leaves[host]; c != nil {
		return c, nil
	}
	dir := filepath.Join(ca.dir, "leaf")
	certFile, keyFile := filepath.Join(dir, host+".der"), filepath.Join(dir, host+".key")
	der, err1 := os.ReadFile(certFile)
	keyPEM, err2 := os.ReadFile(keyFile)
	var key *rsa.PrivateKey
	if err1 == nil && err2 == nil {
		if block, _ := pem.Decode(keyPEM); block != nil {
			key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		}
	}
	if key == nil {
		var err error
		if key, err = rsa.GenerateKey(rand.Reader, keyBits); err != nil {
			return nil, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		if err != nil {
			return nil, err
		}
		// The DSi browser's TLS hello carries no SNI, so the server can't tell which host a connection is
		// for and we can't reliably pick a per-host cert. Put every shop hostname (and wildcards) in one
		// cert's SAN list, so it validates whatever host the console connects to.
		tmpl := &x509.Certificate{
			SerialNumber:       serial,
			Subject:            pkix.Name{Country: []string{"US"}, Organization: []string{"homebrew-eshop"}, CommonName: host},
			DNSNames:           ShopSANs(host),
			NotBefore:          time.Date(2008, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:           time.Date(2049, 12, 31, 0, 0, 0, 0, time.UTC),
			KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			SignatureAlgorithm: x509.SHA1WithRSA,
		}
		if der, err = x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certFile, der, 0o644); err != nil {
			return nil, err
		}
	}
	// Send the CA too, in case the DSi wants the chain spelled out (it already has the CA, so it's harmless).
	c := &tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key}
	ca.leaves[host] = c
	return c, nil
}
