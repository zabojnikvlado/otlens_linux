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

func TestSMBMidstreamResyncSkipsBogusCiphertextLength(t *testing.T) {
	e := New(core.NewEventBus(), true)
	msg := make([]byte, 64)
	copy(msg[:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(msg[4:6], 64)
	binary.LittleEndian.PutUint16(msg[12:14], 0)
	frame := append([]byte{0, 0, 0, 64}, msg...)
	// Prefix the valid frame with bytes that contain a zero followed by a
	// plausible but bogus 1 MiB NBSS length. The old parser could latch onto
	// that zero and wait indefinitely instead of finding the real SMB frame.
	prefix := []byte{0xaa, 0, 0x10, 0x00, 0x00, 0x55, 0x66, 0x77, 0x88}
	chunk := core.TCPStreamChunk{ConnectionID: "mid", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 445, Timestamp: time.Now(), Midstream: true, Data: append(prefix, frame...)}
	got := e.parseStreamChunk(chunk)
	if len(got) != 1 || got[0].Command != "negotiate" || !got[0].StreamResynced {
		t.Fatalf("unexpected %#v", got)
	}
}

func TestSMBEncryptedTransformVisibleAfterMidstreamResync(t *testing.T) {
	e := New(core.NewEventBus(), true)
	msg := make([]byte, 52)
	copy(msg[:4], []byte{0xfd, 'S', 'M', 'B'})
	frame := append([]byte{0, 0, 0, byte(len(msg))}, msg...)
	chunk := core.TCPStreamChunk{ConnectionID: "enc", SrcIP: "10.1.107.156", DstIP: "10.1.222.128", SrcPort: 55000, DstPort: 445, Timestamp: time.Now(), Midstream: true, Data: append([]byte{1, 2, 3, 4, 5}, frame...)}
	got := e.parseStreamChunk(chunk)
	if len(got) != 1 || !got[0].IsEncrypted || got[0].ClientIP != "10.1.107.156" || got[0].ServerIP != "10.1.222.128" {
		t.Fatalf("unexpected %#v", got)
	}
}
