package dsi

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// Listener does TLS for the DSi: connections that open with an SSLv2-format ClientHello (the shop's
// browser) get LegacyServer, everything else gets crypto/tls with Config. Handshakes run on the first
// Read/Write, in the connection's own goroutine, so a slow client can't block Accept.
type Listener struct {
	net.Listener
	Config *tls.Config
	// Cert picks the certificate for a legacy connection (no SNI) from the client's address.
	Cert func(remote string) (*tls.Certificate, error)
	// Log is told about every legacy handshake (err != nil if it failed).
	Log func(remote string, info *LegacyInfo, err error)
	// ForceLegacy sends every connection to LegacyServer (tests).
	ForceLegacy bool
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &lazyConn{Conn: c, l: l}, nil
}

type lazyConn struct {
	net.Conn
	l    *Listener
	once sync.Once
	conn net.Conn
	err  error
}

type bufConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.br.Read(p) }

func (c *lazyConn) init() {
	c.once.Do(func() {
		br := bufio.NewReader(c.Conn)
		c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		first, err := br.Peek(1)
		c.Conn.SetReadDeadline(time.Time{})
		if err != nil {
			c.err = err
			return
		}
		remote, _, _ := net.SplitHostPort(c.Conn.RemoteAddr().String())
		if first[0]&0x80 != 0 || c.l.ForceLegacy {
			cert, err := c.l.Cert(remote)
			if err != nil {
				c.err = err
				return
			}
			var info *LegacyInfo
			c.conn, info, c.err = LegacyServer(c.Conn, br, cert)
			if c.l.Log != nil {
				c.l.Log(remote, info, c.err)
			}
			return
		}
		c.conn = tls.Server(&bufConn{Conn: c.Conn, br: br}, c.l.Config)
	})
}

func (c *lazyConn) Read(p []byte) (int, error) {
	if c.init(); c.err != nil {
		return 0, c.err
	}
	return c.conn.Read(p)
}

func (c *lazyConn) Write(p []byte) (int, error) {
	if c.init(); c.err != nil {
		return 0, c.err
	}
	return c.conn.Write(p)
}

func (c *lazyConn) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return c.Conn.Close()
}
