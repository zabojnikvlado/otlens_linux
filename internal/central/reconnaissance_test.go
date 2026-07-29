package central

import (
	"testing"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func TestReconChangesDetectsIdentityAndServiceChanges(t *testing.T) {
	previous := &management.ReconResult{
		Hostname: "old-host",
		OS:       "Ubuntu 22.04",
		Services: []management.ReconService{{Port: 22, Transport: "tcp", Service: "ssh", Product: "OpenSSH", Version: "8.9"}},
	}
	current := management.ReconResult{
		Hostname: "new-host",
		OS:       "Ubuntu 24.04",
		Services: []management.ReconService{
			{Port: 22, Transport: "tcp", Service: "ssh", Product: "OpenSSH", Version: "9.6"},
			{Port: 443, Transport: "tcp", Service: "https", Product: "nginx"},
		},
	}
	changes := reconChanges(previous, current)
	if len(changes) < 4 {
		t.Fatalf("expected identity and service changes, got %#v", changes)
	}
	foundOS, foundAdded := false, false
	for _, change := range changes {
		if change.Field == "operating_system" && change.Kind == "changed" {
			foundOS = true
		}
		if change.Field == "service" && change.Kind == "added" && change.Current != "" {
			foundAdded = true
		}
	}
	if !foundOS || !foundAdded {
		t.Fatalf("missing expected changes: %#v", changes)
	}
}

func TestReconChangesCreatesInitialBaseline(t *testing.T) {
	changes := reconChanges(nil, management.ReconResult{Hostname: "server-01"})
	if len(changes) != 1 || changes[0].Kind != "baseline" {
		t.Fatalf("unexpected baseline changes: %#v", changes)
	}
}
