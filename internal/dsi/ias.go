package dsi

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IAS (Identity Authentication Server) is the first service the DSi Shop contacts on a console that has no
// device identity yet (no sys/dev.kp). It asks GenerateKeyPair to mint one, then ConfirmKeyPair.
//
// The Shop expects back an EC device private key plus a signed EC certificate chain in Nintendo's cert
// format, which it hands to the console's ES security module to store as dev.kp. Whether ES accepts a cert
// chain we signed (rather than Nintendo) depends on hiyaCFW's signature patches; this endpoint exists to
// find that out on-console. The returned certs are structurally valid but carry placeholder EC keys and
// signatures (Go's stdlib has no sect233r1), so this is a probe, not a finished implementation.

const IASHost = "ias.t.shop.nintendowifi.net"

// eccCert builds a 0x180-byte Nintendo "signed ECC" certificate: an ECC signature over an ECC public key.
//
//	0x000 u32   signature type (0x00010002 = ECC)
//	0x004 [60]  signature (r||s)
//	0x044 [60]  padding
//	0x080 [64]  issuer (NUL-padded)
//	0x0C0 u32   key type (2 = ECC)
//	0x0C4 [64]  name (NUL-padded)
//	0x104 u32   key id / date
//	0x108 [60]  public key (X||Y)
//	0x144 [60]  padding
func eccCert(issuer, name string, keyID uint32, pub, sig []byte) []byte {
	c := make([]byte, 0x180)
	binary.BigEndian.PutUint32(c[0x000:], 0x00010002)
	copy(c[0x004:0x040], sig)
	copy(c[0x080:0x0C0], issuer)
	binary.BigEndian.PutUint32(c[0x0C0:], 2)
	copy(c[0x0C4:0x104], name)
	binary.BigEndian.PutUint32(c[0x104:], keyID)
	copy(c[0x108:0x144], pub)
	return c
}

// placeholder derives deterministic bytes from a label, so repeated runs for one console are stable and the
// bytes aren't all-zero (some importers reject zero keys), without pretending to be real EC material.
func placeholder(n int, parts ...string) []byte {
	out := make([]byte, 0, n)
	seed := strings.Join(parts, "|")
	for i := 0; len(out) < n; i++ {
		h := sha1.Sum([]byte(fmt.Sprintf("%s#%d", seed, i)))
		out = append(out, h[:]...)
	}
	return out[:n]
}

var soapField = func(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?s)<(?:\w+:)?` + name + `[^>]*>(.*?)</(?:\w+:)?` + name + `>`)
}

func field(body []byte, name string) string {
	if m := soapField(name).FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// ias handles an IAS SOAP POST, always writing a response.
func (h *Handler) ias(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	action := r.Header.Get("SOAPAction")
	action = strings.Trim(action, `"`)
	if i := strings.LastIndexByte(action, '/'); i >= 0 {
		action = action[i+1:]
	}

	uniqueID := field(body, "UniqueId")
	messageID := field(body, "MessageId")
	region := orDefault(field(body, "Region"), "USA")
	country := orDefault(field(body, "Country"), "US")
	consoleID, _ := strconv.ParseUint(uniqueID, 10, 64)
	devID := deviceIDFromUnique(uniqueID)

	switch action {
	case "GenerateKeyPair":
		// The device cert's Key Name must be "TWxxxxxxxx-<16 hex of the console's 64-bit id>" (GBATEK): the
		// console rejects the import (nvSetDeviceKeyPairIntermediate, -4047) unless the 16-hex field at name
		// offset 0xB equals its own id (burned in the TWL CPU; it sends it as UniqueId). The 8-hex "xxxxxxxx"
		// is a per-console value used for tickets, not checked at import; we derive it deterministically.
		tikID := binary.BigEndian.Uint32(placeholder(4, "tik", uniqueID))
		name := fmt.Sprintf("TW%08x-%016x", tikID, consoleID)
		// Real sect233r1 key pair: the console signs its ConfirmKeyPair (and every later EC request) with the
		// private key, so a placeholder key fails at the next step (-4009). The public point goes in the cert;
		// the private scalar is returned as DeviceKey. Derived deterministically from the console id so a retry
		// gets the same key (the real server remembers each device's key too).
		dk, err := deviceKey(consoleID)
		if err != nil {
			http.Error(w, "keygen", http.StatusInternalServerError)
			h.log(r, 500, "(ias GenerateKeyPair keygen: "+err.Error()+")")
			return
		}
		priv := dk.Private
		pub := append(append([]byte(nil), dk.PublicX...), dk.PublicY...) // X||Y, 60 bytes
		// Retail chain: device cert signed by MS00000008 (ECC), MS by CA00000001, CA by Root.
		devCert := eccCert("Root-CA00000001-MS00000008", name, 0x00000002,
			pub, placeholder(0x3C, "devsig", uniqueID))
		msCert := eccCert("Root-CA00000001", "MS00000008", 0x00000002,
			placeholder(0x3C, "mspub"), placeholder(0x3C, "mssig"))
		caCert := eccCert("Root", "CA00000001", 0x00000001,
			placeholder(0x3C, "capub"), placeholder(0x3C, "casig"))
		fields := []kv{
			{"DeviceKey", b64(priv)},
			{"DeviceCert", b64(devCert)},
			{"CertChain", b64(msCert)},
			{"CertChain", b64(caCert)},
		}
		h.writeSOAP(w, r, "GenerateKeyPairResponse", "urn:ias.wsapi.broadon.com", devID, messageID, region, country, fields)
		h.log(r, 200, "(ias GenerateKeyPair -> device "+name+")")
		return

	case "ConfirmKeyPair":
		h.writeSOAP(w, r, "ConfirmKeyPairResponse", "urn:ias.wsapi.broadon.com", devID, messageID, region, country, nil)
		h.log(r, 200, "(ias ConfirmKeyPair -> ok)")
		return
	}
	http.Error(w, "not implemented", http.StatusNotImplemented)
	h.log(r, http.StatusNotImplemented, "(ias "+action+" not implemented)")
}

// deviceKeyCache memoizes the sect233r1 key pair per console id (scalar mul is slow, and a retry must get
// the same key).
var deviceKeyCache sync.Map // consoleID -> *DeviceKeyPair

// deviceKey returns a stable sect233r1 key pair for a console, derived deterministically from its id so the
// server reproduces the same device key across requests without persisting it.
func deviceKey(consoleID uint64) (*DeviceKeyPair, error) {
	if v, ok := deviceKeyCache.Load(consoleID); ok {
		return v.(*DeviceKeyPair), nil
	}
	seed := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("dsi-device-key\x00"), consoleID))
	kp, err := GenerateDeviceKey(&hashReader{seed: seed})
	if err != nil {
		return nil, err
	}
	deviceKeyCache.Store(consoleID, kp)
	return kp, nil
}

// hashReader is a deterministic byte stream: SHA-256(seed || counter), block after block.
type hashReader struct {
	seed [32]byte
	ctr  uint64
	buf  []byte
}

func (h *hashReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(h.buf) == 0 {
			blk := sha256.Sum256(binary.BigEndian.AppendUint64(h.seed[:], h.ctr))
			h.ctr++
			h.buf = blk[:]
		}
		c := copy(p[n:], h.buf)
		h.buf = h.buf[c:]
		n += c
	}
	return n, nil
}

// ecs handles an ECS (ECommerce) SOAP POST. After registration the Shop calls CheckDeviceStatus here;
// later it will do ListTitles, purchases and ticket delivery. For now this answers the calls we've reached
// with a minimal successful reply, and logs the rest so we can see what the Shop asks next.
func (h *Handler) ecs(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	action := strings.Trim(r.Header.Get("SOAPAction"), `"`)
	if i := strings.LastIndexByte(action, '/'); i >= 0 {
		action = action[i+1:]
	}
	messageID := field(body, "MessageId")
	devID := deviceIDFromUnique(field(body, "DeviceId"))
	region := orDefault(field(body, "Region"), "USA")
	country := orDefault(field(body, "Country"), "US")

	switch action {
	case "CheckDeviceStatus":
		fields := []kv{
			{"ServiceStandbyMode", "false"},
			{"Balance", ""}, // placeholder; filled when we model points
		}
		h.writeSOAP(w, r, "CheckDeviceStatusResponse", "urn:ecs.wsapi.broadon.com", devID, messageID, region, country, fields)
		h.log(r, 200, "(ecs CheckDeviceStatus -> ok)")
	default:
		// Answer with a bare successful envelope so the Shop proceeds, and log the action to implement next.
		h.writeSOAP(w, r, action+"Response", "urn:ecs.wsapi.broadon.com", devID, messageID, region, country, nil)
		h.log(r, 200, "(ecs "+action+" -> stub ok)")
	}
}

type kv struct{ k, v string }

// writeSOAP writes an EC-style SOAP response: the common header fields the library parses (Version,
// DeviceId, MessageId, TimeStamp, ErrorCode 0, ServiceStandbyMode) plus the action's own fields.
func (h *Handler) writeSOAP(w http.ResponseWriter, r *http.Request, respName, ns string, devID int64, messageID, region, country string, fields []kv) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` + "\n")
	b.WriteString("<soapenv:Body>\n")
	fmt.Fprintf(&b, `<%s xmlns="%s">`+"\n", respName, ns)
	fmt.Fprintf(&b, "<Version>%s</Version>\n", "2.0")
	fmt.Fprintf(&b, "<DeviceId>%d</DeviceId>\n", devID)
	fmt.Fprintf(&b, "<MessageId>%s</MessageId>\n", xmlEscape(messageID))
	fmt.Fprintf(&b, "<TimeStamp>%d</TimeStamp>\n", time.Now().Unix())
	b.WriteString("<ErrorCode>0</ErrorCode>\n")
	b.WriteString("<ServiceStandbyMode>false</ServiceStandbyMode>\n")
	for _, f := range fields {
		fmt.Fprintf(&b, "<%s>%s</%s>\n", f.k, f.v, f.k)
	}
	fmt.Fprintf(&b, "</%s>\n", respName)
	b.WriteString("</soapenv:Body>\n</soapenv:Envelope>\n")

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	io.WriteString(w, b.String())
}

func deviceIDFromUnique(unique string) int64 {
	n, err := strconv.ParseUint(unique, 10, 64)
	if err != nil || n == 0 {
		return 0x10000001
	}
	// The EC DeviceId is a 32-bit value; fold the 64-bit UniqueId into it and keep the top bit set as real
	// NG ids do.
	return int64(uint32(n)|0x10000000) & 0xFFFFFFFF
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
