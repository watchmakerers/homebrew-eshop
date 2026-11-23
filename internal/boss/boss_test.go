package boss

import (
	"bytes"
	"os"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16) // a stand-in, not the console's key
	in := File{Serial: 0x34952b, Payload: Payload{ProgramID: 0x0004001000021900, DataType: 0x10001, NsDataID: 7, Version: 3, Data: []byte("hello bgm")}}
	b, err := Seal(key, in)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:4]) != "boss" || len(b) != 0x28+0x132+0x13C+9 {
		t.Fatalf("bad container: %d bytes", len(b))
	}
	out, err := Open(key, b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Serial != in.Serial || out.Payload.ProgramID != in.Payload.ProgramID || out.Payload.NsDataID != 7 ||
		out.Payload.Version != 3 || out.Payload.DataType != 0x10001 || string(out.Payload.Data) != "hello bgm" {
		t.Errorf("round trip: %+v", out)
	}
	if _, err := Open(bytes.Repeat([]byte{1}, 16), b); err == nil {
		t.Error("wrong key accepted")
	}
}

// With BOSS_KEY_FILE set (a key dumped from your own console), the archived eShop music must decrypt and pass
// both hash checks: proof that the key and this format are right.
func TestArchivedBGM(t *testing.T) {
	keyFile := os.Getenv("BOSS_KEY_FILE")
	if keyFile == "" {
		t.Skip("BOSS_KEY_FILE not set")
	}
	key, err := LoadKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../bgm/archive/US/US_BGM1.boss")
	if err != nil {
		t.Skip(err)
	}
	f, err := Open(key, b)
	if err != nil {
		t.Fatal(err)
	}
	head := f.Payload.Data
	if len(head) > 600 {
		head = head[:600]
	}
	t.Logf("serial %#x program %016X type %#x nsdata %d version %d, %d bytes\n%q", f.Serial, f.Payload.ProgramID,
		f.Payload.DataType, f.Payload.NsDataID, f.Payload.Version, len(f.Payload.Data), head)
}
