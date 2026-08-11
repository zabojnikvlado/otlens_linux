package detect

import (
	"testing"
	"time"

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

func TestExternalCommunicationUDPReplyStaysOutbound(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	t0 := time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC)

	e.handleExternalCommunication(core.Packet{
		Timestamp:  t0,
		SrcIP:      "10.1.222.65",
		DstIP:      "20.101.57.9",
		SrcPort:    55000,
		DstPort:    123,
		L4Protocol: "UDP",
	})
	e.handleExternalCommunication(core.Packet{
		Timestamp:  t0.Add(500 * time.Millisecond),
		SrcIP:      "20.101.57.9",
		DstIP:      "10.1.222.65",
		SrcPort:    123,
		DstPort:    55000,
		L4Protocol: "UDP",
	})

	outbound := e.alerts["external|outbound|10.1.222.65|20.101.57.0/24"]
	if outbound == nil {
		t.Fatal("outbound UDP request did not generate an outbound alert")
	}
	if e.alerts["external|inbound|10.1.222.65|20.101.57.0/24"] != nil {
		t.Fatalf("UDP response was incorrectly classified as an inbound external connection: %#v", e.alerts)
	}
	if outbound.Evidence["response_correlated"] != true {
		t.Fatalf("expected response packet to be correlated with outbound flow, evidence=%#v", outbound.Evidence)
	}
}

func TestExternalCommunicationUnsolicitedUDPIsInbound(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	e.handleExternalCommunication(core.Packet{
		Timestamp:  time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC),
		SrcIP:      "91.228.165.146",
		DstIP:      "10.1.222.14",
		SrcPort:    40000,
		DstPort:    161,
		L4Protocol: "UDP",
	})

	alert := e.alerts["external|inbound|10.1.222.14|91.228.165.0/24"]
	if alert == nil {
		t.Fatal("unsolicited public UDP datagram did not generate inbound alert")
	}
	if alert.Severity != "high" {
		t.Fatalf("unexpected inbound severity: %q", alert.Severity)
	}
}

func TestExternalCommunicationTCPSynAckReplyStaysOutbound(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	t0 := time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC)

	e.handleExternalCommunication(core.Packet{
		Timestamp:  t0,
		SrcIP:      "10.1.222.65",
		DstIP:      "8.8.8.8",
		SrcPort:    51000,
		DstPort:    443,
		L4Protocol: "TCP",
		TCPFlags:   "SYN",
	})
	e.handleExternalCommunication(core.Packet{
		Timestamp:  t0.Add(50 * time.Millisecond),
		SrcIP:      "8.8.8.8",
		DstIP:      "10.1.222.65",
		SrcPort:    443,
		DstPort:    51000,
		L4Protocol: "TCP",
		TCPFlags:   "SYN,ACK",
	})

	if e.alerts["external|outbound|10.1.222.65|8.8.8.0/24"] == nil {
		t.Fatal("outbound TCP handshake did not generate outbound alert")
	}
	if e.alerts["external|inbound|10.1.222.65|8.8.8.0/24"] != nil {
		t.Fatalf("TCP SYN-ACK reply was incorrectly classified as inbound: %#v", e.alerts)
	}
}

func TestExternalCommunicationTCPPublicSynIsInbound(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	t0 := time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC)

	e.handleExternalCommunication(core.Packet{
		Timestamp:  t0,
		SrcIP:      "91.228.165.146",
		DstIP:      "10.1.222.14",
		SrcPort:    52000,
		DstPort:    22,
		L4Protocol: "TCP",
		TCPFlags:   "SYN",
	})
	e.handleExternalCommunication(core.Packet{
		Timestamp:  t0.Add(50 * time.Millisecond),
		SrcIP:      "10.1.222.14",
		DstIP:      "91.228.165.146",
		SrcPort:    22,
		DstPort:    52000,
		L4Protocol: "TCP",
		TCPFlags:   "SYN,ACK",
	})

	alert := e.alerts["external|inbound|10.1.222.14|91.228.165.0/24"]
	if alert == nil {
		t.Fatal("public TCP SYN did not generate inbound alert")
	}
	if e.alerts["external|outbound|10.1.222.14|91.228.165.0/24"] != nil {
		t.Fatalf("inbound TCP connection was incorrectly duplicated as outbound: %#v", e.alerts)
	}
}

func TestExternalCommunicationTCPMidstreamPublicPacketDoesNotInventInbound(t *testing.T) {
	e := newExternalCommunicationTestEngine()
	e.handleExternalCommunication(core.Packet{
		Timestamp:  time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC),
		SrcIP:      "8.8.8.8",
		DstIP:      "10.1.222.65",
		SrcPort:    443,
		DstPort:    51000,
		L4Protocol: "TCP",
		TCPFlags:   "ACK",
	})
	if len(e.alerts) != 0 {
		t.Fatalf("mid-stream TCP data without initiator evidence must not create a false inbound alert: %#v", e.alerts)
	}
}
