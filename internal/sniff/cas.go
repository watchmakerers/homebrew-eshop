package sniff

import (
	"fmt"
	"strconv"
	"strings"

	"homebrew-eshop/internal/catalog"
)

// cas answers the catalog service. NIM (not the eShop app) asks it, with ListTitlesEx, for the price and license
// of a title before buying it; with no reply the shop shows 005-4704.
//
// Reply layout from NIM's parsers (Titles 0x1267f0, Prices entry 0x136448, Price 0x127fa4, Limits 0x127454):
//
//	<Titles>                        one per title
//	  <TitleId>16 hex digits</TitleId>
//	  <Contents><TitleIncluded/><ContentIndex/>...</Contents>   optional
//	  <Attributes>...</Attributes>  optional
//	  <Ratings><Name/><Rating/><Age/><Descriptors/></Ratings>  optional
//	  <Prices>
//	    <ItemId>n</ItemId>
//	    <Price><Amount/><Currency/></Price>
//	    <Limits><Limits>n</Limits><LimitKind>PR|TR|DR|SR|LR|ET</LimitKind></Limits>   up to 8
//	    <LicenseKind>PERMANENT|DEMO|TRIAL|RENTAL|SUBSCRIPT|SERVICE</LicenseKind>
//	  </Prices>
//	</Titles>
//
// Every title we serve is free, with a permanent license.
func (s *Stubs) cas(body []byte) *stubReply {
	a, ok := parseSOAP(body, "urn:cas.wsapi.broadon.com")
	if !ok || a.XMLName.Local != "ListTitlesEx" {
		return nil
	}
	currency := currencies[strings.ToUpper(a.Region)]
	if currency == "" {
		currency = "USD"
	}
	var titles strings.Builder
	n := 0
	for _, raw := range a.TitleIDs {
		tid, err := strconv.ParseUint(strings.TrimSpace(raw), 16, 64)
		if err != nil {
			continue
		}
		t := s.Shop.byInstallID(tid)
		if t == nil {
			continue
		}
		n++
		titles.WriteString("<Titles>" + el("TitleId", fmt.Sprintf("%016X", tid)) +
			"<Prices>" + el("ItemId", strconv.Itoa(ShopID(*t))) +
			"<Price>" + el("Amount", "0") + el("Currency", currency) + "</Price>" +
			"<Limits>" + el("Limits", "0") + el("LimitKind", "PR") + "</Limits>" +
			el("LicenseKind", "PERMANENT") + "</Prices></Titles>")
	}
	r := soapReply(a, el("ServiceStandbyMode", "false")+el("ListResultTotalSize", strconv.Itoa(n))+titles.String())
	r.name = fmt.Sprintf("cas ListTitlesEx (%d of %d titles known)", n, len(a.TitleIDs))
	return r
}

// byInstallID finds the installable title the shop announced under this 3DS title ID: the one from its CIA when
// that has been read, else the placeholder titleID() gave it.
func (s *Shop) byInstallID(tid uint64) *catalog.Title {
	s.mu.Lock()
	src := s.byTitleID[tid]
	s.mu.Unlock()
	for _, t := range s.Titles() {
		if t.CIA == nil {
			continue
		}
		if (src != nil && t.CIA == src) || t.TitleID == tid || titleID(&t) == tid {
			t := t
			return &t
		}
	}
	return nil
}
