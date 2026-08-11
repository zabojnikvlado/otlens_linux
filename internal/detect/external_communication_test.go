package detect

import (
	"testing"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func newExternalCommunicationTestEngine() *Engine {
	return &Engine{
		alerts: make(map[string]*Alert),
		rules:  builtinRules(),
	}
}

func TestExternalCommunicationIgnoresMulticastAndSpecialUse(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	for _, dst := range []string{
		"224.0.0.22",      // IGMPv3 membership reports
		"239.255.255.250", // SSDP
		"255.255.255.255", // limited broadcast
		"169.254.1.1",     // link-local
		"100.64.0.1",      // CGNAT/shared space
		"198.18.0.1",      // benchmarking
		"203.0.113.10",    // documentation
	} {
		e.handleExternalCommunication(core.Packet{SrcIP: "10.1.222.181", DstIP: dst})
	}
	if len(e.alerts) != 0 {
		t.Fatalf("special-use traffic generated external communication alerts: %#v", e.alerts)
	}
}

func TestExternalCommunicationAcceptsPublicUnicast(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	e.handleExternalCommunication(core.Packet{SrcIP: "10.1.222.107", DstIP: "8.8.8.8"})

	alert := e.alerts["external|outbound|10.1.222.107|8.8.8.0/24"]
	if alert == nil {
		t.Fatal("public Internet communication did not generate an alert")
	}
	if alert.Type != AlertExternalCommunication || alert.IP != "10.1.222.107" || alert.Count != 1 {
		t.Fatalf("unexpected alert: %#v", alert)
	}
}

func TestExternalCommunicationAcceptsInboundPublicUnicast(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	e.handleExternalCommunication(core.Packet{SrcIP: "91.228.165.146", DstIP: "10.1.222.14"})

	if alert := e.alerts["external|inbound|10.1.222.14|91.228.165.0/24"]; alert == nil {
		t.Fatal("inbound public Internet communication did not generate an alert")
	}
}

func TestExternalCommunicationApprovalScopeIsDestinationNetwork(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	e.handleExternalCommunication(core.Packet{SrcIP: "10.1.222.10", DstIP: "8.8.8.8"})
	e.handleExternalCommunication(core.Packet{SrcIP: "10.1.222.10", DstIP: "1.1.1.1"})
	if e.alerts["external|outbound|10.1.222.10|8.8.8.0/24"] == nil || e.alerts["external|outbound|10.1.222.10|1.1.1.0/24"] == nil {
		t.Fatalf("distinct public destination networks must remain separately approvable: %#v", e.alerts)
	}
}
