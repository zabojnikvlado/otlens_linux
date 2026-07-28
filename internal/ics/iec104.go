package ics

import "github.com/zabojnikvlado/otlens_linux/internal/core"

var iecTypes = map[byte]string{1: "SinglePoint", 3: "DoublePoint", 9: "MeasuredNormalized", 11: "MeasuredScaled", 13: "MeasuredFloat", 30: "SinglePointTime", 45: "SingleCommand", 46: "DoubleCommand", 47: "RegulatingStepCommand", 48: "SetPointNormalized", 49: "SetPointScaled", 50: "SetPointFloat", 100: "Interrogation", 103: "ClockSync", 105: "ResetProcess", 107: "TestCommandTime"}

func parseIEC104(p core.Packet) (Message, bool) {
	b := p.AppPayload
	if len(b) < 6 || b[0] != 0x68 || int(b[1])+2 > len(b) {
		return Message{}, false
	}
	m := newMessage(p, "IEC 60870-5-104")
	m.IsResponse = p.SrcPort == PortIEC104
	if len(b) == 6 {
		m.FunctionName = "U/S-format"
		return m, true
	}
	typ := b[6]
	m.FunctionCode = typ
	m.FunctionName = iecTypes[typ]
	if m.FunctionName == "" {
		m.FunctionName = "ASDU"
	}
	m.Details["type_id"] = typ
	if typ >= 45 && typ <= 50 || typ == 103 || typ == 105 {
		m.Details["security_relevant"] = true
	}
	return m, true
}
