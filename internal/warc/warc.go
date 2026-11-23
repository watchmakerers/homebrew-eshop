// Package warc reads the HTTP responses stored in WARC files (.warc or .warc.gz, including the usual
// one-gzip-member-per-record layout).
//
// A WARC record is a "WARC/1.x" line, header lines, a blank line, Content-Length bytes of block, then two CRLFs.
// For "response" records the block is the raw HTTP response.
package warc

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
)

// Response is one archived HTTP response.
type Response struct {
	URI    string // WARC-Target-URI
	Status int
	Header http.Header
	Body   []byte
}

// MaxBody skips responses bigger than this (videos); their bodies aren't read.
const MaxBody = 32 << 20

// Each calls fn for every HTTP response record in the file. Returning an error from fn stops the walk.
func Each(path string, fn func(*Response) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = bufio.NewReaderSize(f, 1<<20)
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		gz.Multistream(true) // one member per record, read as one stream
		r = gz
	}
	return each(bufio.NewReaderSize(r, 1<<20), fn)
}

func each(br *bufio.Reader, fn func(*Response) error) error {
	tp := textproto.NewReader(br)
	for {
		line, err := tp.ReadLine()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if line == "" {
			continue // the CRLFs between records
		}
		if !strings.HasPrefix(line, "WARC/") {
			return fmt.Errorf("expected a WARC record, got %q", truncate(line, 40))
		}
		h, err := tp.ReadMIMEHeader()
		if err != nil {
			return err
		}
		n, err := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("record with bad Content-Length %q", h.Get("Content-Length"))
		}
		block := io.LimitReader(br, n)
		if h.Get("WARC-Type") == "response" && strings.HasPrefix(h.Get("Content-Type"), "application/http") {
			rec, err := readResponse(block, h.Get("WARC-Target-URI"))
			if err == nil && rec != nil {
				if err := fn(rec); err != nil {
					return err
				}
			}
		}
		if _, err := io.Copy(io.Discard, block); err != nil { // whatever wasn't read
			return err
		}
	}
}

func readResponse(block io.Reader, uri string) (*Response, error) {
	br := bufio.NewReader(block)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > MaxBody {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	if len(body) > MaxBody {
		return nil, nil
	}
	return &Response{URI: strings.Trim(uri, "<>"), Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Record builds a response record, for tests and for writing small WARCs.
func Record(uri string, status int, contentType string, body []byte) []byte {
	var http bytes.Buffer
	fmt.Fprintf(&http, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", status, "X", contentType, len(body))
	http.Write(body)
	var rec bytes.Buffer
	fmt.Fprintf(&rec, "WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: %s\r\nContent-Type: application/http; msgtype=response\r\nContent-Length: %d\r\n\r\n", uri, http.Len())
	rec.Write(http.Bytes())
	rec.WriteString("\r\n\r\n")
	return rec.Bytes()
}
