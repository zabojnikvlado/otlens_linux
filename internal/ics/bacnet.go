package ics

import "github.com/zabojnikvlado/otlens_linux/internal/core"

var bacnetServices = map[byte]string{0: "AcknowledgeAlarm", 5: "SubscribeCOV", 12: "ReadProperty", 14: "ReadPropertyMultiple", 15: "WriteProperty", 16: "WritePropertyMultiple", 17: "DeviceCommunicationControl", 20: "ReinitializeDevice", 26: "ReadRange"}
var bacnetUnconfirmed = map[byte]string{0: "I-Am", 2: "UnconfirmedCOVNotification", 8: "Who-Is", 7: "Who-Has", 6: "TimeSynchronization"}

func parseBACnet(p core.Packet) (Message, bool) {
	b := p.AppPayload
	if len(b) < 6 || b[0] != 0x81 {
		return Message{}, false
	}
	m := newMessage(p, "BACnet/IP")
	m.IsResponse = p.SrcPort == PortBACnet
	m.Details["bvlc_function"] = b[1]
	// Original-Unicast/Broadcast-NPDU starts APDU after four-byte BVLC plus compact NPDU.
	off := 4
	if len(b) <= off {
		return m, true
	}
	if b[off] != 0x01 {
		return Message{}, false
	}
	off += 2
	if len(b) <= off {
		return m, true
	}
	pdu := b[off] >> 4
	m.Details["pdu_type"] = pdu
	if pdu == 1 && len(b) > off+3 {
		svc := b[off+3]
		m.FunctionCode = svc
		m.FunctionName = bacnetServices[svc]
	}
	if pdu == 0 && len(b) > off+3 {
		svc := b[off+3]
		m.FunctionCode = svc
		m.FunctionName = bacnetServices[svc]
	}
	if pdu == 1 && len(b) > off+1 {
		svc := b[off+1]
		m.FunctionCode = svc
		m.FunctionName = bacnetUnconfirmed[svc]
	}
	if m.FunctionName == "" {
		m.FunctionName = "BVLC/NPDU"
	}
	if m.FunctionName == "WriteProperty" || m.FunctionName == "WritePropertyMultiple" || m.FunctionName == "DeviceCommunicationControl" || m.FunctionName == "ReinitializeDevice" {
		m.Details["security_relevant"] = true
	}
	return m, true
}
