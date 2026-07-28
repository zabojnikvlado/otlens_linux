package recon

import (
	"net"
	"testing"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func TestDeniedTargetPolicy(t *testing.T) {
	p := management.ReconPolicy{AllowedNetworks: []string{"10.0.0.0/8"}, DeniedTargets: []string{"10.1.2.3"}}
	if !denied(net.ParseIP("10.1.2.3"), p) {
		t.Fatal("explicit deny must win")
	}
	if denied(net.ParseIP("10.2.3.4"), p) {
		t.Fatal("allowed network target was denied")
	}
	if !denied(net.ParseIP("192.0.2.1"), p) {
		t.Fatal("target outside allowlist must be denied")
	}
}

func TestServiceNames(t *testing.T) {
	if serviceName(445) != "smb" || serviceName(502) != "modbus" || serviceName(65000) != "unknown" {
		t.Fatal("unexpected service classification")
	}
}
