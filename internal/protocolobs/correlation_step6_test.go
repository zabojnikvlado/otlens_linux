package protocolobs

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

func TestSIPDialogLifecycleAndFailures(t *testing.T) {
	c := NewCorrelator(time.Second)
	now := time.Unix(200_000, 0)
	a := correlationContext("sip-conversation", udpconversation.DirectionAToB)
	b := correlationContext("sip-conversation", udpconversation.DirectionBToA)
	steps := []struct {
		at      time.Duration
		payload string
		context udpconversation.ParseContext
	}{
		{0, sipRequest("INVITE", "call-1", "1 INVITE", "from-1", ""), a},
		{10 * time.Millisecond, sipResponse(100, "call-1", "1 INVITE", "from-1", "to-1"), b},
		{50 * time.Millisecond, sipResponse(180, "call-1", "1 INVITE", "from-1", "to-1"), b},
		{100 * time.Millisecond, sipResponse(200, "call-1", "1 INVITE", "from-1", "to-1"), b},
		{110 * time.Millisecond, sipRequest("ACK", "call-1", "1 ACK", "from-1", "to-1"), a},
		{time.Second, sipRequest("BYE", "call-1", "2 BYE", "from-1", "to-1"), a},
	}
	var result []any
	for _, step := range steps {
		result = c.Observe(core.Packet{Timestamp: now.Add(step.at), SrcPort: 5060, DstPort: 5060, AppPayload: []byte(step.payload)}, step.context)
	}
	dialog := result[0].(SIPDialog)
	if dialog.CallID != "call-1" || dialog.TimeToResponse != 10*time.Millisecond ||
		dialog.RingingTime != 50*time.Millisecond || dialog.Duration != 900*time.Millisecond ||
		dialog.Status != "200" || dialog.Failed || dialog.Abandoned {
		t.Fatalf("unexpected SIP dialog: %#v", dialog)
	}

	failed := NewCorrelator(time.Second)
	failed.Observe(core.Packet{Timestamp: now, SrcPort: 5060, DstPort: 5060, AppPayload: []byte(sipRequest("INVITE", "failed", "1 INVITE", "f", ""))}, a)
	failure := failed.Observe(core.Packet{Timestamp: now.Add(time.Millisecond), SrcPort: 5060, DstPort: 5060, AppPayload: []byte(sipResponse(486, "failed", "1 INVITE", "f", "t"))}, b)
	if len(failure) != 1 || !failure[0].(SIPDialog).Failed {
		t.Fatalf("failed call not reported: %#v", failure)
	}
	if malformed := c.Observe(core.Packet{SrcPort: 5060, DstPort: 5060, AppPayload: []byte("bad")}, a); malformed != nil {
		t.Fatalf("malformed SIP produced state: %#v", malformed)
	}
}

func TestSIPParallelDuplicateWrongIDAndTimeout(t *testing.T) {
	c := NewCorrelator(time.Second)
	now := time.Unix(210_000, 0)
	a := correlationContext("sip", udpconversation.DirectionAToB)
	b := correlationContext("sip", udpconversation.DirectionBToA)
	for _, id := range []string{"one", "two"} {
		c.Observe(core.Packet{Timestamp: now, SrcPort: 5060, DstPort: 5060, AppPayload: []byte(sipRequest("INVITE", id, "1 INVITE", "f", ""))}, a)
	}
	// Duplicate/wrong-call responses must not complete either valid dialog.
	c.Observe(core.Packet{Timestamp: now, SrcPort: 5060, DstPort: 5060, AppPayload: []byte(sipResponse(180, "one", "1 INVITE", "f", "t"))}, b)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 5060, DstPort: 5060, AppPayload: []byte(sipResponse(180, "one", "1 INVITE", "f", "t"))}, b)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 5060, DstPort: 5060, AppPayload: []byte(sipResponse(180, "wrong", "1 INVITE", "f", "t"))}, b)
	expired := c.Expire(now.Add(6 * time.Minute))
	if len(expired) != 3 {
		t.Fatalf("SIP timeout count = %d", len(expired))
	}
}

func sipRequest(method, callID, cseq, fromTag, toTag string) string {
	return fmt.Sprintf("%s sip:user@example.test SIP/2.0\r\nCall-ID: %s\r\nCSeq: %s\r\nFrom: <sip:a@test>;tag=%s\r\nTo: <sip:b@test>;tag=%s\r\n\r\n", method, callID, cseq, fromTag, toTag)
}

func sipResponse(status int, callID, cseq, fromTag, toTag string) string {
	return fmt.Sprintf("SIP/2.0 %d Status\r\nCall-ID: %s\r\nCSeq: %s\r\nFrom: <sip:a@test>;tag=%s\r\nTo: <sip:b@test>;tag=%s\r\n\r\n", status, callID, cseq, fromTag, toTag)
}

func TestDTLSHandshakeRetransmissionTimeoutParallelMalformed(t *testing.T) {
	c := NewCorrelator(100 * time.Millisecond)
	now := time.Unix(220_000, 0)
	a := correlationContext("dtls-one", udpconversation.DirectionAToB)
	b := correlationContext("dtls-one", udpconversation.DirectionBToA)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 443, AppPayload: dtlsRecord(1, 0, 1)}, a)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 443, AppPayload: dtlsRecord(1, 0, 1)}, a)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 443, DstPort: 1, AppPayload: dtlsRecord(3, 0, 2)}, b)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 443, AppPayload: dtlsRecord(1, 0, 3)}, a)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 443, DstPort: 1, AppPayload: dtlsRecord(2, 0, 4)}, b)
	result := c.Observe(core.Packet{Timestamp: now.Add(10 * time.Millisecond), SrcPort: 443, DstPort: 1, AppPayload: dtlsRecord(20, 1, 5)}, b)
	handshake := result[0].(DTLSHandshake)
	if handshake.Status != "complete" || handshake.Retransmissions != 1 || handshake.Version != "0xfeff" || handshake.Epoch != 1 {
		t.Fatalf("unexpected DTLS handshake: %#v", handshake)
	}
	c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 443, AppPayload: dtlsRecord(1, 0, 1)}, correlationContext("dtls-two", udpconversation.DirectionAToB))
	c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 443, AppPayload: dtlsRecord(1, 0, 1)}, correlationContext("dtls-three", udpconversation.DirectionAToB))
	if malformed := c.Observe(core.Packet{SrcPort: 1, DstPort: 443, AppPayload: []byte{1}}, a); malformed != nil {
		t.Fatalf("malformed DTLS produced state: %#v", malformed)
	}
	if expired := c.Expire(now.Add(time.Second)); len(expired) != 2 {
		t.Fatalf("DTLS timeout count = %d", len(expired))
	}
}

func dtlsRecord(handshake byte, epoch uint16, sequence uint64) []byte {
	data := make([]byte, 14)
	data[0], data[1], data[2] = 22, 0xfe, 0xff
	binary.BigEndian.PutUint16(data[3:5], epoch)
	for i := 0; i < 6; i++ {
		data[10-i] = byte(sequence)
		sequence >>= 8
	}
	data[13] = handshake
	return data
}

func TestOpenVPNStateResetControlKeepaliveTimeoutMalformed(t *testing.T) {
	c := NewCorrelator(100 * time.Millisecond)
	now := time.Unix(230_000, 0)
	context := correlationContext("vpn-one", udpconversation.DirectionAToB)
	for index, opcode := range []byte{7, 4, 5} {
		result := c.Observe(core.Packet{Timestamp: now.Add(time.Duration(index) * time.Millisecond), SrcPort: 1, DstPort: 1194, AppPayload: []byte{opcode << 3, 0}}, context)
		if len(result) != 1 {
			t.Fatalf("OpenVPN state not published for opcode %d", opcode)
		}
	}
	session := c.openvpn["vpn-one:0"]
	if session.Resets != 1 || session.Handshakes != 1 || session.ControlPackets != 3 || session.Keepalives != 1 {
		t.Fatalf("unexpected OpenVPN state: %#v", session)
	}
	c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 1194, AppPayload: []byte{7 << 3, 0}}, correlationContext("vpn-two", udpconversation.DirectionAToB))
	if malformed := c.Observe(core.Packet{SrcPort: 1, DstPort: 1194, AppPayload: []byte{0}}, context); malformed != nil {
		t.Fatalf("malformed OpenVPN produced state: %#v", malformed)
	}
	if expired := c.Expire(now.Add(time.Second)); len(expired) != 2 {
		t.Fatalf("OpenVPN timeout count = %d", len(expired))
	}
}

func TestBitTorrentPairingParallelDuplicateWrongIDTimeoutMalformed(t *testing.T) {
	c := NewCorrelator(100 * time.Millisecond)
	now := time.Unix(240_000, 0)
	a := correlationContext("bt", udpconversation.DirectionAToB)
	b := correlationContext("bt", udpconversation.DirectionBToA)
	for index, action := range []uint32{0, 1, 2} {
		c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 6969, AppPayload: btRequest(action, uint32(index+1))}, a)
	}
	result := c.Observe(core.Packet{Timestamp: now.Add(10 * time.Millisecond), SrcPort: 6969, DstPort: 1, AppPayload: btResponse(1, 2)}, b)
	if len(result) != 1 || result[0].(BitTorrentExchange).Operation != "announce" || result[0].(BitTorrentExchange).RTT != 10*time.Millisecond {
		t.Fatalf("unexpected BitTorrent exchange: %#v", result)
	}
	if duplicate := c.Observe(core.Packet{Timestamp: now, SrcPort: 6969, DstPort: 1, AppPayload: btResponse(1, 2)}, b); duplicate != nil {
		t.Fatalf("duplicate response paired: %#v", duplicate)
	}
	if wrong := c.Observe(core.Packet{Timestamp: now, SrcPort: 6969, DstPort: 1, AppPayload: btResponse(0, 99)}, b); wrong != nil {
		t.Fatalf("wrong transaction paired: %#v", wrong)
	}
	if malformed := c.Observe(core.Packet{SrcPort: 1, DstPort: 6969, AppPayload: []byte{1}}, a); malformed != nil {
		t.Fatalf("malformed BitTorrent produced state: %#v", malformed)
	}
	if expired := c.Expire(now.Add(time.Second)); len(expired) != 2 {
		t.Fatalf("BitTorrent timeout count = %d", len(expired))
	}
}

func btRequest(action, transaction uint32) []byte {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], 0x41727101980)
	binary.BigEndian.PutUint32(data[8:12], action)
	binary.BigEndian.PutUint32(data[12:16], transaction)
	return data
}

func btResponse(action, transaction uint32) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], action)
	binary.BigEndian.PutUint32(data[4:8], transaction)
	return data
}
