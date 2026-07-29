# Asset identity and lifecycle

Central now derives a stable canonical identity for each current asset from the durable topology ledger.

- Assets with a MAC address use `mac:<normalized-mac>` and remain one identity across DHCP/IP changes.
- Assets without a MAC address use `ip:<address>` and are marked lower-confidence.
- Identity metadata includes first/last seen, active/stale state, known IP aliases, source count and confidence.
- The Assets tab can filter active versus stale identities.
- Asset Detail includes a Lifecycle panel with the canonical identity and IP history summary.

An asset is considered active when its durable identity was seen within the last ten minutes. This is independent from confirmation/security state.
