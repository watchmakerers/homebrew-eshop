package sniff

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultPatterns are the hostnames sent to this PC. With Nimbus's Pretendo or Youmakai patches the console's
// http patch has already rewritten nintendo.net / nintendowifi.net to pretendo.cc, so both spellings are listed.
// Everything else (logins, conntest, Pretendo game servers) is forwarded to the upstream resolver untouched.
var DefaultPatterns = []string{
	"*.shop.nintendo.net", "*.shop.nintendowifi.net", "*.shop.pretendo.cc",
}

// DNS answers A queries for hostnames matching Patterns with AnswerIP and forwards everything else to Upstream.
// Every query is recorded, intercepted or not, so the log shows each host the console looks up.
type DNS struct {
	Upstream string // host:port
	AnswerIP netip.Addr
	Patterns []string
	// AllowAny answers clients outside private/loopback ranges. Off by default: a resolver reachable from the
	// internet gets abused for amplification attacks.
	AllowAny bool
	Rec      *Recorder

	client *dns.Client
}

func (d *DNS) Match(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, p := range d.Patterns {
		if ok, _ := path.Match(strings.ToLower(p), name); ok {
			return true
		}
	}
	return false
}

func (d *DNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	from := remoteAddr(w.RemoteAddr())
	if !d.AllowAny && !(from.IsPrivate() || from.IsLoopback() || from.IsLinkLocalUnicast()) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}
	if len(req.Question) == 1 {
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		hit := d.Match(name)
		line := ""
		if d.Rec.FirstTime(name) {
			mark := "    forwarded "
			if hit {
				mark = "--> INTERCEPT "
			}
			line = fmt.Sprintf("DNS %s%s (%s, from %s)", mark, name, dns.TypeToString[q.Qtype], from)
		}
		d.Rec.Record(Event{Kind: "dns", From: from.String(), Name: name, QType: dns.TypeToString[q.Qtype], Intercepted: hit}, line)

		if hit {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			if q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.IP(d.AnswerIP.AsSlice()),
				})
			} // other types (AAAA etc.): empty answer, so the console uses the A record
			w.WriteMsg(m)
			return
		}
	}

	if d.client == nil {
		d.client = &dns.Client{Timeout: 5 * time.Second}
	}
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		d.client.Net = "tcp"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, _, err := d.client.ExchangeContext(ctx, req, d.Upstream)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	w.WriteMsg(resp)
}

func remoteAddr(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

// LANAddr guesses this PC's LAN address: the source address the OS would use to reach upstream. A UDP
// "dial" sends no packets.
func LANAddr(upstream string) (netip.Addr, error) {
	c, err := net.Dial("udp4", upstream)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return remoteAddr(c.LocalAddr()), nil
}
