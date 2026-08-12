package asset

import (
	"testing"
	"time"
)

func TestRestorePreservesConfirmedState(t *testing.T) {
	e := NewEngine(nil, 100)
	assets := []*Asset{{MAC: "00:11:22:33:44:55", IP: "10.0.0.1", Confirmed: false}}
	e.Restore(assets)
	if got := e.Get("00:11:22:33:44:55"); got == nil || got.Confirmed {
		t.Fatal("Restore() unexpectedly changed Confirmed")
	}
}

func TestRestorePreservesUnverifiedBindingProvenance(t *testing.T) {
	e := NewEngine(nil, 100)
	mac := "00:11:22:33:44:55"
	e.Restore([]*Asset{{MAC: mac, IP: "10.0.0.1", Confirmed: true, IPVerificationKnown: true, IPVerifiedByARP: false}})
	e.Update("10.0.0.2", mac, "", time.Now(), false, false, 0)
	if got := e.Get(mac); got == nil || got.IP != "10.0.0.2" {
		t.Fatalf("unverified restored binding did not follow a new direct observation: %#v", got)
	}
}

func TestRestorePreservesVerifiedBindingUntilARPChangesIt(t *testing.T) {
	e := NewEngine(nil, 100)
	mac := "00:11:22:33:44:55"
	e.Restore([]*Asset{{MAC: mac, IP: "10.0.0.1", Confirmed: true, IPVerificationKnown: true, IPVerifiedByARP: true}})
	e.Update("203.0.113.8", mac, "", time.Now(), false, false, 0)
	if got := e.Get(mac); got == nil || got.IP != "10.0.0.1" {
		t.Fatalf("routed non-ARP observation overwrote verified binding: %#v", got)
	}
	e.Update("10.0.0.2", mac, "", time.Now().Add(time.Second), true, false, 0)
	if got := e.Get(mac); got == nil || got.IP != "10.0.0.2" || !got.IPVerifiedByARP {
		t.Fatalf("new ARP evidence did not move verified binding: %#v", got)
	}
}

func TestRestoreCanonicalizesMACIdentity(t *testing.T) {
	e := NewEngine(nil, 100)
	e.Restore([]*Asset{{MAC: "00-11-22-33-44-55", IP: "10.0.0.1", Confirmed: true}})
	if got := e.Get("00:11:22:33:44:55"); got == nil || got.MAC != "00:11:22:33:44:55" {
		t.Fatalf("restored MAC identity was not canonicalized: %#v", got)
	}
	if e.Count() != 1 {
		t.Fatalf("unexpected restored asset count: %d", e.Count())
	}
}
