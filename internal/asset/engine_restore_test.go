package asset

import "testing"

func TestRestorePreservesConfirmedState(t *testing.T) {
 e:=&Engine{}
 assets:=[]*Asset{{Confirmed:false}}
 e.Restore(assets)
 if assets[0].Confirmed {
   t.Fatal("Restore() unexpectedly changed Confirmed")
 }
}
