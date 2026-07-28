package smb

import (
	"encoding/binary"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"testing"
	"time"
)

func TestSMBRecordSplitAcrossStreamChunks(t *testing.T) {
	e := New(core.NewEventBus(), true)
	msg := make([]byte, 64)
	copy(msg[:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(msg[4:6], 64)
	binary.LittleEndian.PutUint16(msg[12:14], 0)
	frame := append([]byte{0, 0, 0, 64}, msg...)
	base := core.TCPStreamChunk{ConnectionID: "x", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 445, Timestamp: time.Now()}
	a := base
	a.Data = frame[:20]
	if got := e.parseStreamChunk(a); len(got) != 0 {
		t.Fatalf("premature parse: %d", len(got))
	}
	b := base
	b.Data = frame[20:]
	got := e.parseStreamChunk(b)
	if len(got) != 1 || got[0].Command != "negotiate" {
		t.Fatalf("unexpected %#v", got)
	}
}
