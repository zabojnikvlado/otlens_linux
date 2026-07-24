package ics

import "github.com/zabojnikvlado/otlens_linux/internal/core"

type profinetParser struct{}

func (profinetParser) Name() string { return "PROFINET DCP" }
func (profinetParser) CanParse(p core.Packet) bool {
	return p.EtherType == "PROFINET" || p.EtherType == "UnknownEthernetType" && len(p.AppPayload) >= 2 && p.AppPayload[0] >= 0xfe
}
func (profinetParser) Parse(p core.Packet) (Message, bool) {
	b := p.AppPayload
	if len(b) < 12 {
		return Message{}, false
	}
	frameID, _ := u16be(b, 0)
	if frameID < 0xfefe || frameID > 0xfeff {
		return Message{}, false
	}
	m := newMessage(p, "PROFINET DCP")
	m.FunctionCode = b[2]
	services := map[byte]string{3: "Get", 4: "Set", 5: "Identify", 6: "Hello"}
	m.FunctionName = services[b[2]]
	if m.FunctionName == "" {
		m.FunctionName = "DCP"
	}
	m.Details["frame_id"] = frameID
	m.Details["service_type"] = b[3]
	if b[2] == 4 {
		m.Details["security_relevant"] = true
	}
	return m, true
}
