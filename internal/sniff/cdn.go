package sniff

import (
	"context"
	"errors"
	"fmt"
	"image"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/cia"
)

// The CDN NIM downloads installs from (3dbrew "CDN"): /ccs/download/<title ID>/tmd[.<version>] is the TMD with
// its CP and CA certs appended, and /ccs/download/<title ID>/<content ID> is one content as stored (encrypted with
// the title key when its TMD record says so). A CIA holds exactly these, so every title is served from its CIA:
// local files as they are, remote ones after Shop.CIAs has downloaded them.
var cdnPath = regexp.MustCompile(`^/ccs/download/([0-9A-Fa-f]{16})/(tmd(?:\.([0-9]+))?|[0-9A-Fa-f]{8})$`)

// How long requests wait. The title page and ec_info only need the CIA's header and TMD (a quick Range read
// for remote CIAs, while the full download runs in the background); the CDN needs the whole file, and by then
// the console is installing and shows progress, so it waits for the download.
const (
	pageWait = 15 * time.Second
	cdnWait  = 10 * time.Minute
)

// installInfo is what the console is told about a title's CIA, read from the CIA itself.
type installInfo struct {
	src     *catalog.CIASource
	titleID uint64
	version uint16
	size    int64  // sum of the contents in the file
	ticket  []byte // the CIA's ticket, signature included
	certs   []byte // the CIA's cert chain
}

// prepare reads the title's CIA header and TMD and remembers which CIA serves its title ID. For a remote CIA it
// also starts the full download.
func (s *Shop) prepare(ctx context.Context, t *catalog.Title) (*installInfo, error) {
	if t.CIA == nil {
		return nil, fmt.Errorf("%s: no CIA", t.Name)
	}
	var c *cia.File
	var err error
	switch {
	case t.CIA.Path != "":
		c, err = parsePath(t.CIA.Path)
	case s.CIAs != nil:
		c, err = s.CIAs.Info(ctx, t.CIA)
	default:
		err = errors.New("remote CIA and no download cache")
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", t.Name, err)
	}
	info := &installInfo{src: t.CIA, titleID: c.TitleID, version: c.TitleVersion, ticket: c.Ticket, certs: c.Certs}
	for _, ct := range c.Contents {
		if ct.Present() {
			info.size += int64(ct.Size)
		}
	}
	s.mu.Lock()
	if s.prepared == nil {
		s.prepared = map[string]*installInfo{}
		s.byTitleID = map[uint64]*catalog.CIASource{}
	}
	s.prepared[t.Key()] = info
	s.byTitleID[c.TitleID] = t.CIA
	s.mu.Unlock()
	return info, nil
}

func parsePath(p string) (*cia.File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return cia.Parse(f)
}

// prepareFor is prepare with a time limit. On failure callers fall back to the catalog's numbers.
func (s *Shop) prepareFor(t *catalog.Title, wait time.Duration) (*installInfo, error) {
	s.mu.Lock()
	info := s.prepared[t.Key()]
	s.mu.Unlock()
	if info != nil {
		return info, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return s.prepare(ctx, t)
}

// ciaForTitleID finds the CIA file for a title ID the console asks the CDN for, waiting for a remote one to
// finish downloading.
func (s *Shop) ciaForTitleID(tid uint64) (string, error) {
	s.mu.Lock()
	src := s.byTitleID[tid]
	s.mu.Unlock()
	if src == nil {
		// Not prepared yet (e.g. after a restart): any title the shop could have announced under this ID.
		for _, t := range s.Titles() {
			if t.CIA == nil || (t.TitleID != tid && titleID(&t) != tid) || (t.CIA.Path == "" && s.CIAs == nil) {
				continue
			}
			t := t
			info, err := s.prepareFor(&t, pageWait)
			if err != nil {
				return "", err
			}
			if info.titleID == tid {
				src = t.CIA
				break
			}
		}
	}
	if src == nil {
		return "", nil
	}
	if src.Path != "" {
		return src.Path, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cdnWait)
	defer cancel()
	return s.CIAs.Path(ctx, src)
}

// cdn answers a CDN request, or returns nil (404) for anything it doesn't have.
func (s *Shop) cdn(path string) *stubReply {
	m := cdnPath.FindStringSubmatch(path)
	if m == nil {
		return nil
	}
	tid, _ := strconv.ParseUint(m[1], 16, 64)
	p, err := s.ciaForTitleID(tid)
	if err != nil {
		return &stubReply{name: "cdn error: " + err.Error(), contentType: "text/plain", body: []byte("error\n"), status: http.StatusInternalServerError}
	}
	if p == "" {
		return nil
	}
	f, err := os.Open(p)
	if err != nil {
		return &stubReply{name: "cdn error: " + err.Error(), contentType: "text/plain", body: []byte("error\n"), status: http.StatusInternalServerError}
	}
	c, err := cia.Parse(f)
	if err != nil || c.TitleID != tid {
		f.Close()
		return nil
	}

	if m[2] == "tmd" || m[3] != "" {
		defer f.Close()
		if m[3] != "" {
			if v, _ := strconv.Atoi(m[3]); v != int(c.TitleVersion) {
				return nil // only the version in the file
			}
		}
		tmd, err := c.CDNTMD()
		if err != nil {
			return &stubReply{name: "cdn tmd error: " + err.Error(), contentType: "text/plain", body: []byte("error\n"), status: http.StatusInternalServerError}
		}
		return &stubReply{name: fmt.Sprintf("cdn tmd %016X", tid), contentType: "application/octet-stream", body: tmd}
	}

	id, _ := strconv.ParseUint(m[2], 16, 32)
	ct, ok := c.Content(uint32(id))
	if !ok || !ct.Present() {
		f.Close()
		return nil
	}
	return &stubReply{
		name:        fmt.Sprintf("cdn content %016X/%08x (%d bytes)", tid, ct.ID, ct.Size),
		contentType: "application/octet-stream",
		serve: func(w http.ResponseWriter, r *http.Request) {
			defer f.Close()
			http.ServeContent(w, r, "", time.Time{}, c.Reader(ct)) // handles Range, for resumed downloads
		},
	}
}

// ciaIcon is the 48x48 icon from the title's CIA, if the CIA is on this machine (or already downloaded) and has
// one. It never starts or waits for a download.
func (s *Shop) ciaIcon(t *catalog.Title) image.Image {
	if t.CIA == nil {
		return nil
	}
	p := t.CIA.Path
	if p == "" && s.CIAs != nil {
		p, _ = s.CIAs.Ready(t.CIA)
	}
	if p == "" {
		return nil
	}
	c, err := parsePath(p)
	if err != nil || c.SMDH == nil {
		return nil
	}
	return c.SMDH.Icon()
}
