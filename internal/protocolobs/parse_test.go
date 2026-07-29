package protocolobs

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestHTTP(t *testing.T) {
	c := core.TCPStreamChunk{Timestamp: time.Now(), SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 50000, DstPort: 80, Data: []byte("GET /status HTTP/1.1\r\nHost: plc.local\r\nUser-Agent: test\r\n\r\n")}
	o, ok := parseHTTP(c, c.Data)
	if !ok || o.Host != "plc.local" || o.Resource != "/status" {
		t.Fatalf("unexpected observation: %#v", o)
	}
}
func TestDHCP(t *testing.T) {
	d := make([]byte, 244)
	d[0] = 1
	binary.BigEndian.PutUint32(d[236:240], 0x63825363)
	d[240] = 53
	d[241] = 1
	d[242] = 1
	d[243] = 255
	p := core.Packet{Timestamp: time.Now(), SrcPort: 68, DstPort: 67, AppPayload: d}
	o, ok := parseDHCP(p, d)
	if !ok || o.Operation != "discover" {
		t.Fatalf("unexpected observation: %#v", o)
	}
}
func TestSSH(t *testing.T) {
	c := core.TCPStreamChunk{Timestamp: time.Now(), SrcPort: 22, DstPort: 50000}
	o, ok := parseSSH(c, []byte("SSH-2.0-OpenSSH_9.6\r\n"))
	if !ok || o.Attributes["banner"] == "" {
		t.Fatal("SSH banner not parsed")
	}
}

func TestKerberosASReq(t *testing.T) {
	p := core.Packet{SrcPort: 55000, DstPort: 88, AppPayload: []byte{0x6a, 0x01, 0x00}}
	o, ok := parseKerberosUDP(p, p.AppPayload)
	if !ok || o.Protocol != "kerberos" || o.Operation != "as_req" {
		t.Fatalf("unexpected: %#v %v", o, ok)
	}
}

func TestDCERPCRequest(t *testing.T) {
	d := make([]byte, 16)
	d[0] = 5
	d[2] = 0
	d[4] = 0x10
	binary.LittleEndian.PutUint16(d[8:10], 16)
	binary.LittleEndian.PutUint32(d[12:16], 42)
	o, ok := parseDCERPC(core.TCPStreamChunk{}, d)
	if !ok || o.Operation != "request" || o.Attributes["call_id"] != "42" {
		t.Fatalf("unexpected: %#v %v", o, ok)
	}
}

func TestNFSv3Read(t *testing.T) {
	d := make([]byte, 24)
	binary.BigEndian.PutUint32(d[4:8], 0)
	binary.BigEndian.PutUint32(d[8:12], 2)
	binary.BigEndian.PutUint32(d[12:16], 100003)
	binary.BigEndian.PutUint32(d[16:20], 3)
	binary.BigEndian.PutUint32(d[20:24], 6)
	o, ok := parseONCRPC(baseUDP(core.Packet{}, "nfs"), d)
	if !ok || o.Operation != "read" {
		t.Fatalf("unexpected: %#v %v", o, ok)
	}
}

func TestMSSQLPrelogin(t *testing.T) {
	d := []byte{18, 1, 0, 8, 0, 0, 1, 0}
	o, ok := parseMSSQL(core.TCPStreamChunk{}, d)
	if !ok || o.Operation != "prelogin" {
		t.Fatalf("unexpected: %#v %v", o, ok)
	}
}

func TestDTLSClientHello(t *testing.T) {
	d := make([]byte, 14)
	d[0] = 22
	d[1] = 0xfe
	d[2] = 0xfd
	d[13] = 1
	o, ok := parseDTLS(core.Packet{}, d)
	if !ok || o.Operation != "client_hello" {
		t.Fatalf("unexpected: %#v %v", o, ok)
	}
}

func TestOpenVPN(t *testing.T) {
	o, ok := parseOpenVPN(baseUDP(core.Packet{}, "openvpn"), []byte{7 << 3, 0})
	if !ok || o.Operation != "control_hard_reset_client_v2" {
		t.Fatalf("unexpected: %#v %v", o, ok)
	}
}

func TestBitTorrentHandshake(t *testing.T) {
	d := append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...)
	o, ok := parseBitTorrentTCP(core.TCPStreamChunk{}, d)
	if !ok || o.Operation != "handshake" {
		t.Fatalf("unexpected: %#v %v", o, ok)
	}
}
