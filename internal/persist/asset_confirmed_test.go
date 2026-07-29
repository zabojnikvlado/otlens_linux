package persist

import (
	"path/filepath"
	"testing"

	"github.com/zabojnikvlado/otlens_linux/internal/asset"
)

func TestAssetConfirmedStateRoundTrip(t *testing.T) {
	t.Parallel()

	db, err := Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})

	want := []*asset.Asset{
		{MAC: "00:11:22:33:44:55", Confirmed: false},
		{MAC: "00:11:22:33:44:66", Confirmed: true},
	}
	if err := syncKeyed(db, bucketAssets, want, func(item *asset.Asset) string {
		return item.MAC
	}); err != nil {
		t.Fatalf("syncKeyed() failed: %v", err)
	}

	got, err := loadKeyed[*asset.Asset](db, bucketAssets)
	if err != nil {
		t.Fatalf("loadKeyed() failed: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("loaded %d assets, want %d", len(got), len(want))
	}

	states := make(map[string]bool, len(got))
	for _, item := range got {
		states[item.MAC] = item.Confirmed
	}
	if states[want[0].MAC] {
		t.Fatalf("unconfirmed state for %q was not preserved", want[0].MAC)
	}
	if !states[want[1].MAC] {
		t.Fatalf("confirmed state for %q was not preserved", want[1].MAC)
	}
}
