package sniff

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"homebrew-eshop/internal/catalog"
	"homebrew-eshop/internal/cia"
	"homebrew-eshop/internal/cia/ciatest"
)

func ecsRequest(action, fields string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ecs="urn:ecs.wsapi.broadon.com"><SOAP-ENV:Body>` +
		`<ecs:` + action + `><ecs:Version>2.0</ecs:Version><ecs:MessageId>EC-1-1</ecs:MessageId><ecs:DeviceId>1</ecs:DeviceId><ecs:Region>JPN</ecs:Region>` +
		fields + `</ecs:` + action + `></SOAP-ENV:Body></SOAP-ENV:Envelope>`)
}

func TestPurchaseAndTickets(t *testing.T) {
	const tid = 0x000400000BA1A700
	path := filepath.Join(t.TempDir(), "game.cia")
	os.WriteFile(path, ciatest.Build(ciatest.Spec{TitleID: tid, Contents: []ciatest.Content{{ID: 0, Data: make([]byte, 64)}}}), 0o644)
	titles := []catalog.Title{{Name: "Game", TitleID: tid, CIA: &catalog.CIASource{Path: path}}}
	st := &Stubs{Shop: &Shop{Titles: func() []catalog.Title { return titles }}}
	call := func(body []byte) []byte {
		t.Helper()
		req := httptest.NewRequest("POST", "https://ecs.c.shop.pretendo.cc/ecs/services/ECommerceSOAP", nil)
		r := st.Respond("ecs.c.shop.pretendo.cc", req, body)
		if r == nil {
			t.Fatalf("no reply to %s", body)
		}
		return r.body
	}

	var buy struct {
		Pairs []struct {
			TitleID  string `xml:"TitleId"`
			TicketID string `xml:"TicketId"`
		} `xml:"Body>AccountPurchaseTitleResponse>TitleIdTicketId"`
		Amount string `xml:"Body>AccountPurchaseTitleResponse>Balance>Amount"`
	}
	b := call(ecsRequest("AccountPurchaseTitle", `<ecs:ItemId>1</ecs:ItemId><ecs:TitleId>000400000BA1A700</ecs:TitleId>`))
	if err := xml.Unmarshal(b, &buy); err != nil || len(buy.Pairs) != 1 || buy.Pairs[0].TitleID != "000400000BA1A700" || buy.Pairs[0].TicketID == "" || buy.Pairs[0].TicketID == "0" || buy.Amount != "0" {
		t.Fatalf("purchase reply %v: %s", err, b)
	}

	var get struct {
		Tickets []string `xml:"Body>AccountGetETicketsResponse>ETickets"`
		Certs   []string `xml:"Body>AccountGetETicketsResponse>Certs"`
	}
	b = call(ecsRequest("AccountGetETickets", `<ecs:TicketId>`+buy.Pairs[0].TicketID+`</ecs:TicketId><ecs:DeviceCert>x</ecs:DeviceCert>`))
	if err := xml.Unmarshal(b, &get); err != nil || len(get.Tickets) != 1 || len(get.Certs) != 2 {
		t.Fatalf("tickets reply %v: %s", err, b)
	}
	ticket, _ := base64.StdEncoding.DecodeString(get.Tickets[0])
	sig, _ := cia.SignatureLen(binary.BigEndian.Uint32(ticket))
	got := binary.BigEndian.Uint64(ticket[sig+ticketIDOffset:])
	if s := strings.TrimSpace(buy.Pairs[0].TicketID); s != uintStr(got) {
		t.Errorf("ticket's own ID %d doesn't match the announced %s", got, s)
	}
	for _, c := range get.Certs {
		raw, _ := base64.StdEncoding.DecodeString(c)
		if l, err := cia.SplitCerts(raw); err != nil || len(l) != 1 || (!strings.HasPrefix(l[0].Name, "CA") && !strings.HasPrefix(l[0].Name, "XS")) {
			t.Errorf("cert %v %v", l, err)
		}
	}

	// A ticket we never issued stays unanswered.
	req := httptest.NewRequest("POST", "https://ecs.c.shop.pretendo.cc/ecs/services/ECommerceSOAP", nil)
	if r := st.Respond("ecs.c.shop.pretendo.cc", req, ecsRequest("AccountGetETickets", `<ecs:TicketId>123</ecs:TicketId>`)); r != nil {
		t.Errorf("unknown ticket answered: %s", r.body)
	}
}

func uintStr(v uint64) string { return strconv.FormatUint(v, 10) }

// The eShop app's own path: prepurchase_info, ninja !purchase, then NIM fetching that ticket.
func TestNinjaPurchaseFlow(t *testing.T) {
	const tid = 0x000400000BA1A700
	path := filepath.Join(t.TempDir(), "game.cia")
	os.WriteFile(path, ciatest.Build(ciatest.Spec{TitleID: tid, Contents: []ciatest.Content{{ID: 0, Data: make([]byte, 64)}}}), 0o644)
	titles := []catalog.Title{{Name: "Game", TitleID: tid, CIA: &catalog.CIASource{Path: path}}}
	st := &Stubs{Shop: &Shop{Titles: func() []catalog.Title { return titles }}}
	sid := strconv.Itoa(ShopID(titles[0]))
	get := func(method, url string, body []byte) []byte {
		t.Helper()
		req := httptest.NewRequest(method, url, nil)
		r := st.Respond(req.Host, req, body)
		if r == nil {
			t.Fatalf("no reply to %s", url)
		}
		return r.body
	}

	var pre struct {
		P struct {
			Content struct {
				Pay struct {
					Price struct {
						PreOrder *bool `json:"pre_order"`
						Regular  struct {
							ID  int    `json:"id"`
							Raw string `json:"raw_value"`
						} `json:"regular_price"`
					} `json:"price"`
					Total struct {
						Raw string `json:"raw_value"`
					} `json:"total_amount"`
				} `json:"payment_amount"`
			} `json:"purchasing_content"`
		} `json:"prepurchase_info"`
	}
	b := get("GET", "https://ninja.ctr.shop.pretendo.cc/ninja/ws/JP/title/"+sid+"/prepurchase_info", nil)
	if err := json.Unmarshal(b, &pre); err != nil || pre.P.Content.Pay.Price.PreOrder == nil || pre.P.Content.Pay.Price.Regular.Raw != "0" || pre.P.Content.Pay.Total.Raw != "0" {
		t.Fatalf("prepurchase_info: %v %s", err, b)
	}

	var buy struct {
		R struct {
			TicketID uint64 `json:"ticket_id"`
			Balance  struct {
				Raw string `json:"raw_value"`
			} `json:"post_balance"`
		} `json:"transaction_result"`
	}
	b = get("POST", "https://ninja.ctr.shop.pretendo.cc/ninja/ws/JP/title/"+sid+"/!purchase", nil)
	if err := json.Unmarshal(b, &buy); err != nil || buy.R.TicketID == 0 || buy.R.Balance.Raw != "0" {
		t.Fatalf("!purchase: %v %s", err, b)
	}

	b = get("POST", "https://ecs.c.shop.pretendo.cc/ecs/services/ECommerceSOAP",
		ecsRequest("AccountGetETickets", `<ecs:TicketId>`+strconv.FormatUint(buy.R.TicketID, 10)+`</ecs:TicketId>`))
	if !strings.Contains(string(b), "<ETickets>") {
		t.Fatalf("ticket not served after !purchase: %s", b)
	}
}
