// Package sniff records what the 3DS eShop app asks for: a DNS server that sends eShop hostnames to this PC
// and an HTTP(S) server that logs every request it gets.
package sniff

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Recorder writes every event as a JSON line to events.jsonl in Dir, request bodies to Dir/bodies, and a
// one-line summary to Out.
type Recorder struct {
	Dir string
	Out io.Writer

	mu   sync.Mutex
	f    *os.File
	seq  int
	seen map[string]bool // DNS names already printed, so repeat lookups don't flood the terminal
}

func NewRecorder(dir string, out io.Writer) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Join(dir, "bodies"), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Recorder{Dir: dir, Out: out, f: f, seen: map[string]bool{}}, nil
}

func (r *Recorder) Close() error { return r.f.Close() }

// Event is one line of events.jsonl. Kind is dns, tls_hello, http or error.
type Event struct {
	Seq  int       `json:"seq"`
	Time time.Time `json:"time"`
	Kind string    `json:"kind"`
	From string    `json:"from,omitempty"`

	// dns
	Name        string `json:"name,omitempty"`
	QType       string `json:"qtype,omitempty"`
	Intercepted bool   `json:"intercepted,omitempty"`

	// tls_hello
	SNI      string   `json:"sni,omitempty"`
	Versions []string `json:"versions,omitempty"`
	Ciphers  []string `json:"ciphers,omitempty"`

	// http
	Listener   string              `json:"listener,omitempty"` // http or https
	Method     string              `json:"method,omitempty"`
	Host       string              `json:"host,omitempty"`
	URI        string              `json:"uri,omitempty"`
	Header     map[string][]string `json:"header,omitempty"`
	TLS        *TLSInfo            `json:"tls,omitempty"`
	BodyLen    int                 `json:"body_len,omitempty"`
	BodyFile   string              `json:"body_file,omitempty"`
	Status     int                 `json:"status,omitempty"`
	ServedFile string              `json:"served_file,omitempty"`

	Message string `json:"message,omitempty"`
}

type TLSInfo struct {
	Version    string `json:"version"`
	Cipher     string `json:"cipher"`
	ClientCert string `json:"client_cert,omitempty"` // subject of the certificate the console sent, if any
	ClientCA   string `json:"client_cert_issuer,omitempty"`
}

// Record numbers the event, writes it, and prints line (if non-empty).
func (r *Recorder) Record(e Event, line string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	e.Seq, e.Time = r.seq, time.Now()
	if data, err := json.Marshal(e); err == nil {
		r.f.Write(append(data, '\n'))
	}
	if line != "" && r.Out != nil {
		fmt.Fprintf(r.Out, "%s #%-4d %s\n", e.Time.Format("15:04:05"), e.Seq, line)
	}
	return e.Seq
}

// FirstTime reports whether key hasn't been seen before (and marks it seen).
func (r *Recorder) FirstTime(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[key] {
		return false
	}
	r.seen[key] = true
	return true
}

// SaveBody stores a request body and returns its path relative to Dir.
func (r *Recorder) SaveBody(body []byte) (string, error) {
	r.mu.Lock()
	n := r.seq + 1 // the number the request's event is about to get (best effort; only for the file name)
	r.mu.Unlock()
	name := filepath.Join("bodies", fmt.Sprintf("%06d-%d.bin", n, time.Now().UnixNano()))
	return name, os.WriteFile(filepath.Join(r.Dir, name), body, 0o600)
}

// Writer adapts the recorder for log.Logger (used for net/http's TLS handshake errors).
func (r *Recorder) Writer(kind string) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		msg := string(p)
		for len(msg) > 0 && msg[len(msg)-1] == '\n' {
			msg = msg[:len(msg)-1]
		}
		r.Record(Event{Kind: "error", Message: kind + ": " + msg}, "!! "+kind+": "+msg)
		return len(p), nil
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
