package ics

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestOPCUASecureChannelLifecycleIsNotCritical(t *testing.T) {
	m, ok := parseOPCUA(core.Packet{Timestamp: time.Now(), L4Protocol: "TCP", SrcPort: 50000, DstPort: PortOPCUA, AppPayload: []byte{'O', 'P', 'N', 'F', 8, 0, 0, 0}})
	if !ok {
		t.Fatal("OPC UA fixture not parsed")
	}
	if m.Details["operation_class"] != "session" {
		t.Fatalf("unexpected operation class: %#v", m.Details)
	}
	if v, _ := m.Details["security_relevant"].(bool); v {
		t.Fatalf("OpenSecureChannel must not be a blanket critical ICS operation")
	}
}

func TestIEC104ClockSyncHasTimeSemanticsNotBlanketCritical(t *testing.T) {
	m, ok := parseIEC104(core.Packet{Timestamp: time.Now(), L4Protocol: "TCP", SrcPort: 50000, DstPort: PortIEC104, AppPayload: []byte{0x68, 5, 0, 0, 0, 0, 103}})
	if !ok {
		t.Fatal("IEC104 fixture not parsed")
	}
	if v, _ := m.Details["is_time_change"].(bool); !v {
		t.Fatalf("ClockSync missing time-change semantic: %#v", m.Details)
	}
	if v, _ := m.Details["security_relevant"].(bool); v {
		t.Fatalf("ClockSync must be policy-evaluated, not blanket critical")
	}
}

func TestModbusMultipleWriteIsDetectedWithoutScalarValue(t *testing.T) {
	payload := []byte{0, 1, 0, 0, 0, 8, 1, 16, 0, 1, 0, 1, 2, 0, 42}
	m, ok := parseModbus(core.Packet{Timestamp: time.Now(), L4Protocol: "TCP", SrcPort: 50000, DstPort: 502, AppPayload: payload}, 502)
	if !ok {
		t.Fatal("Modbus fixture not parsed")
	}
	if v, _ := m.Details["is_write"].(bool); !v {
		t.Fatalf("WriteMultipleRegisters was not normalized as a write: %#v", m.Details)
	}
}

func TestSemanticConfigurationChange(t *testing.T) {
	m := Message{Details: map[string]interface{}{}}
	setOperation(&m, "config", true, true, false)
	if v, _ := m.Details["is_config_change"].(bool); !v {
		t.Fatalf("config semantic not set")
	}
	if v, _ := m.Details["security_relevant"].(bool); v {
		t.Fatalf("configuration change should use its dedicated high-severity rule, not legacy blanket critical")
	}
}

func TestMalformedFrameGuardRequiresProtocolSignature(t *testing.T) {
	random := []byte{0xde, 0xad, 0xbe, 0xef}
	if looksLikeICSFrame("Modbus", random) {
		t.Fatal("short arbitrary TCP fragment was treated as a malformed Modbus frame")
	}
	modbus := []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}
	if !looksLikeICSFrame("Modbus", modbus) {
		t.Fatal("valid Modbus MBAP signature was not recognized")
	}
}
