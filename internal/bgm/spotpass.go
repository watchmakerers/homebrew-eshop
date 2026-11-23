package bgm

import (
	"fmt"
	"strings"

	"homebrew-eshop/internal/boss"
)

// ShopProgramIDs are the eShop app's title IDs, which the BOSS payload names as its owner (KR and TW unverified).
var ShopProgramIDs = map[string]uint64{
	"JP": 0x0004001000020900, "US": 0x0004001000021900, "EU": 0x0004001000022900,
	"KR": 0x0004001000027900, "TW": 0x0004001000028900,
}

// SpotPassFile wraps a slot's payload in an encrypted BOSS container for the eShop of region. The version is
// the season's start date (YYYYMMDD), so each new season is a new file to the console.
// DataType and NsDataID are unverified guesses: decrypting the archived US_BGM1.boss (boss.TestArchivedBGM)
// shows the real ones.
func SpotPassFile(key []byte, region string, slot int, w Window, payload []byte) ([]byte, error) {
	pid, ok := ShopProgramIDs[strings.ToUpper(region)]
	if !ok {
		return nil, fmt.Errorf("unknown eShop region %q", region)
	}
	version := uint32(w.Begin.Year()*10000 + int(w.Begin.Month())*100 + w.Begin.Day())
	return boss.Seal(key, boss.File{
		Serial:  uint64(w.Begin.Unix()),
		Payload: boss.Payload{ProgramID: pid, DataType: 0x10001, NsDataID: uint32(slot), Version: version, Data: payload},
	})
}
