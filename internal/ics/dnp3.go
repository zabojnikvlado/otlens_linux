package ics

import "github.com/zabojnikvlado/otlens_linux/internal/core"

var dnpFunctions = map[byte]string{0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate", 5: "DirectOperate", 6: "DirectOperateNoAck", 7: "ImmediateFreeze", 8: "ImmediateFreezeNoAck", 9: "FreezeClear", 10: "FreezeClearNoAck", 13: "ColdRestart", 14: "WarmRestart", 18: "StopApplication", 19: "SaveConfiguration", 20: "EnableUnsolicited", 21: "DisableUnsolicited", 23: "DelayMeasurement", 24: "RecordCurrentTime", 129: "Response", 130: "UnsolicitedResponse"}

func parseDNP3(p core.Packet) (Message, bool) {
	b := p.AppPayload
	if len(b) < 10 || b[0] != 0x05 || b[1] != 0x64 {
		return Message{}, false
	}
	m := newMessage(p, "DNP3")
	m.IsResponse = p.SrcPort == PortDNP3
	// Link header is 10 bytes; transport+application control generally precede function.
	off := 12
	if len(b) <= off {
		return Message{}, false
	}
	fc := b[off]
	n := dnpFunctions[fc]
	if n == "" {
		n = "Function"
	}
	m.FunctionCode = fc
	m.FunctionName = n
	if dst, ok := u16le(b, 4); ok {
		m.Details["destination"] = dst
	}
	if src, ok := u16le(b, 6); ok {
		m.Details["source"] = src
	}
	switch fc {
	case 2:
		setOperation(&m, "write", true, true, false)
	case 3:
		setOperation(&m, "select", false, true, false)
	case 4, 5, 6:
		setOperation(&m, "operate", true, true, false)
	case 7, 8, 9, 10:
		setOperation(&m, "process_control", true, true, false)
	case 13, 14, 18:
		setOperation(&m, "mode", true, true, true)
	case 19:
		setOperation(&m, "config", true, true, false)
	case 24:
		setOperation(&m, "time", true, true, false)
	case 1:
		setOperation(&m, "read", false, false, false)
	}
	return m, true
}
