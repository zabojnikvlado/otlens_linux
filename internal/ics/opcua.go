package ics

import "github.com/zabojnikvlado/otlens_linux/internal/core"

var opcTypes = map[string]string{"HEL": "Hello", "ACK": "Acknowledge", "ERR": "Error", "RHE": "ReverseHello", "OPN": "OpenSecureChannel", "CLO": "CloseSecureChannel", "MSG": "SecureMessage"}

func parseOPCUA(p core.Packet) (Message, bool) {
	b := p.AppPayload
	if len(b) < 8 {
		return Message{}, false
	}
	typ := string(b[:3])
	n := opcTypes[typ]
	if n == "" {
		return Message{}, false
	}
	if b[3] != 'F' && b[3] != 'C' && b[3] != 'A' {
		return Message{}, false
	}
	m := newMessage(p, "OPC UA")
	m.FunctionName = n
	m.FunctionCode = b[0]
	m.IsResponse = p.SrcPort == PortOPCUA
	m.Details["message_type"] = typ
	m.Details["chunk_type"] = string([]byte{b[3]})
	if sz, ok := u32le(b, 4); ok {
		m.Details["message_size"] = sz
	}
	if typ == "OPN" || typ == "CLO" {
		m.Details["security_relevant"] = true
	}
	return m, true
}
