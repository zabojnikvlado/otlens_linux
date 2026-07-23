package api

import "github.com/zabojnikvlado/otlens_linux/internal/asset"

// AssetView adds cross-cutting enrichment onto an asset for API
// responses — the OT/IT classification (derived from store.Tag data
// — see topology.Classify) and the MAC vendor (see internal/oui) —
// without asset.Engine itself needing to know about OT protocols or
// vendor databases. Keeping that correlation at the API layer avoids
// coupling the asset engine to store/oui.
type AssetView struct {
	*asset.Asset

	IsOT      bool
	Protocols []string
	Vendor    string
}
