package asset

import "testing"

func TestRestorePreservesConfirmedState(t *testing.T) {
	t.Parallel()

	engine := NewEngine(nil, 0)
	assets := []*Asset{
		{MAC: "00:11:22:33:44:55", IP: "192.0.2.10", Confirmed: false},
		{MAC: "00:11:22:33:44:66", IP: "192.0.2.11", Confirmed: true},
	}

	engine.Restore(assets)

	got := make(map[string]*Asset)
	for _, item := range engine.GetAll() {
		got[item.MAC] = item
	}

	if got[assets[0].MAC] == nil {
		t.Fatalf("unconfirmed asset %q was not restored", assets[0].MAC)
	}
	if got[assets[0].MAC].Confirmed {
		t.Fatalf("Restore() changed unconfirmed asset %q to confirmed", assets[0].MAC)
	}
	if got[assets[1].MAC] == nil {
		t.Fatalf("confirmed asset %q was not restored", assets[1].MAC)
	}
	if !got[assets[1].MAC].Confirmed {
		t.Fatalf("Restore() changed confirmed asset %q to unconfirmed", assets[1].MAC)
	}
}

func TestRestoreReplacesExistingAssetsWithoutConfirmingNewState(t *testing.T) {
	t.Parallel()

	engine := NewEngine(nil, 0)
	engine.Restore([]*Asset{{MAC: "old", Confirmed: true}})
	engine.Restore([]*Asset{{MAC: "new", Confirmed: false}})

	assets := engine.GetAll()
	if len(assets) != 1 {
		t.Fatalf("Restore() returned %d assets, want 1", len(assets))
	}
	if assets[0].MAC != "new" {
		t.Fatalf("Restore() retained MAC %q, want %q", assets[0].MAC, "new")
	}
	if assets[0].Confirmed {
		t.Fatal("Restore() confirmed replacement asset unexpectedly")
	}
}
