package sniff

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"homebrew-eshop/internal/cia"
)

// Buying a title. The eShop app POSTs ninja title/<id>/!purchase; the reply's transaction_result (parser TIGER
// 0x331754: post_balance.raw_value, ticket_id (number, required), transaction_id, integrated_account,
// privilege_infos optional) names the ticket, which NIM then fetches with ECS AccountGetETickets (below).
//
// NIM's own ECS purchase (traced in NIM):
//
//  1. AccountPurchaseTitle(TitleId, ItemId, Price...). The reply (purchaseItem handler, 0x132180) may carry
//     <Balance><Amount/><Currency/></Balance> and <Transactions>..., both optional (parser 0x125fc0), then
//     <TitleIdTicketId><TitleId/><TicketId/></TitleIdTicketId>, the ticket ID in decimal (strtoull base 10).
//  2. AccountGetETickets(TicketId..., DeviceCert). The reply (0x136a5c) has one <ETickets> per requested ticket,
//     base64 of the whole ticket, then <Certs>, base64 of each certificate of the ticket's chain.
//
// We hand out the ticket that's inside the title's own CIA. Its signature isn't Nintendo's for homebrew, so this
// relies on the console's signature patches (Luma3DS has them), as installing the CIA with FBI does.

const ticketIDOffset = 0x90 // in the ticket data, after the signature block

// ticketData returns the ticket's ID and a copy of the ticket whose ID is non-zero: homebrew CIAs often carry ID
// 0, which NIM would read as "no ticket", so those get a stable ID made from the title ID.
func ticketData(info *installInfo) (uint64, []byte, error) {
	t := append([]byte(nil), info.ticket...)
	if len(t) < 4 {
		return 0, nil, fmt.Errorf("CIA has no ticket")
	}
	sig, err := cia.SignatureLen(binary.BigEndian.Uint32(t))
	if err != nil {
		return 0, nil, err
	}
	off := sig + ticketIDOffset
	if len(t) < off+8 {
		return 0, nil, fmt.Errorf("ticket too short")
	}
	id := binary.BigEndian.Uint64(t[off:])
	if id == 0 {
		h := fnv.New64a()
		binary.Write(h, binary.BigEndian, info.titleID)
		id = h.Sum64()&0x0000FFFFFFFFFFFF | 0x0005000000000000
		binary.BigEndian.PutUint64(t[off:], id)
	}
	return id, t, nil
}

func (s *Shop) purchaseTitle(a soapAction) *stubReply {
	currency := currencies[strings.ToUpper(a.Region)]
	if currency == "" {
		currency = "USD"
	}
	var pairs strings.Builder
	var names []string
	for _, raw := range a.TitleIDs {
		tid, err := strconv.ParseUint(strings.TrimSpace(raw), 16, 64)
		if err != nil {
			return nil
		}
		t := s.byInstallID(tid)
		if t == nil {
			return nil // not ours: leave it unanswered (and logged)
		}
		info, err := s.prepareFor(t, pageWait)
		if err != nil {
			return nil
		}
		id, ticket, err := ticketData(info)
		if err != nil {
			return nil
		}
		s.issue(id, ticket, info.certs)
		pairs.WriteString("<TitleIdTicketId>" + el("TitleId", fmt.Sprintf("%016X", tid)) + el("TicketId", strconv.FormatUint(id, 10)) + "</TitleIdTicketId>")
		names = append(names, t.Name)
	}
	if len(names) == 0 {
		return nil
	}
	r := soapReply(a, el("ServiceStandbyMode", "false")+"<Balance>"+el("Amount", "0")+el("Currency", currency)+"</Balance>"+pairs.String())
	r.name = "ecs AccountPurchaseTitle (" + strings.Join(names, ", ") + ")"
	return r
}

type issuedTicket struct {
	ticket []byte
	certs  []byte
}

func (s *Shop) getETickets(a soapAction) *stubReply {
	var tickets, certs strings.Builder
	var chain []byte
	for _, raw := range a.TicketIDs {
		id, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil
		}
		s.mu.Lock()
		it := s.tickets[id]
		s.mu.Unlock()
		if it == nil {
			return nil // a ticket we never issued (e.g. after a restart): leave it unanswered and logged
		}
		tickets.WriteString(el("ETickets", base64.StdEncoding.EncodeToString(it.ticket)))
		if chain == nil {
			chain = it.certs
		}
	}
	if len(a.TicketIDs) == 0 {
		return nil
	}
	list, err := cia.SplitCerts(chain)
	if err != nil {
		return nil
	}
	for _, c := range list {
		if strings.HasPrefix(c.Name, "CA") || strings.HasPrefix(c.Name, "XS") { // the ticket's signers
			certs.WriteString(el("Certs", base64.StdEncoding.EncodeToString(c.Raw)))
		}
	}
	r := soapReply(a, el("ServiceStandbyMode", "false")+tickets.String()+certs.String())
	r.name = fmt.Sprintf("ecs AccountGetETickets (%d)", len(a.TicketIDs))
	return r
}

// ninjaPurchase answers the eShop's ninja title/<id>/!purchase: the title is free, here is its ticket's ID.
func (s *Shop) ninjaPurchase(country string, id int) *stubReply {
	t := s.find(id)
	if t == nil {
		return nil
	}
	info, err := s.prepareFor(t, pageWait)
	if err != nil {
		return nil
	}
	ticketID, ticket, err := ticketData(info)
	if err != nil {
		return nil
	}
	s.issue(ticketID, ticket, info.certs)
	money := moneyIn(country)
	return jsonReply(fmt.Sprintf("ninja !purchase %d (%s): ticket %d", id, t.Name, ticketID), map[string]any{"transaction_result": map[string]any{
		"transaction_id":     ticketID & 0xFFFFFFFF,
		"ticket_id":          ticketID,
		"integrated_account": false,
		"post_balance":       money("0"),
	}})
}

func (s *Shop) issue(id uint64, ticket, certs []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil {
		s.tickets = map[uint64]*issuedTicket{}
	}
	s.tickets[id] = &issuedTicket{ticket: ticket, certs: certs}
}
