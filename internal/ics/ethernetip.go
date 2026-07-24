package ics

import "github.com/zabojnikvlado/otlens_linux/internal/core"

var enipCommands = map[uint16]string{0x0001: "NOP", 0x0004: "ListServices", 0x0063: "ListIdentity", 0x0064: "ListInterfaces", 0x0065: "RegisterSession", 0x0066: "UnregisterSession", 0x006f: "SendRRData", 0x0070: "SendUnitData"}

func parseEtherNetIP(p core.Packet) (Message, bool) {
	b := p.AppPayload
	if len(b) < 24 {
		return Message{}, false
	}
	cmd, _ := u16le(b, 0)
	n, ok := enipCommands[cmd]
	if !ok {
		return Message{}, false
	}
	m := newMessage(p, "EtherNet/IP")
	m.FunctionCode = uint8(cmd)
	m.FunctionName = n
	m.IsResponse = p.SrcPort == PortEtherNetIP
	if s, ok := u32le(b, 4); ok {
		m.Details["session_handle"] = s
	}
	if st, ok := u32le(b, 8); ok {
		m.Details["status"] = st
		m.IsException = st != 0
	}
	if cmd == 0x006f || cmd == 0x0070 {
		m.Details["encapsulation_command"] = n
		if len(b) > 40 {
			svc := b[len(b)-1]
			m.Details["cip_service"] = svc
			if svc == 0x4d || svc == 0x4e || svc == 0x10 || svc == 0x53 {
				m.Details["security_relevant"] = true
			}
		}
	}
	return m, true
}
