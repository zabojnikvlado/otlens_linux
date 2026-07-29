package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUDPConversationConfigDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	udp := config.Capture.UDPConversations
	if !udp.Enabled || udp.IdleTimeout != 30*time.Second || udp.MaxActive != 100_000 ||
		udp.MaxPendingRequests != 256 || udp.RetainPayload ||
		udp.Protocols.DNS.Timeout != 5*time.Second || udp.Protocols.DHCP.Timeout != time.Minute ||
		udp.Protocols.SNMP.Timeout != 10*time.Second || udp.Protocols.SIP.Timeout != 5*time.Minute {
		t.Fatalf("unexpected UDP defaults: %#v", udp)
	}
}
