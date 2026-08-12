# OTLens — Asset Identity/IP-MAC hardening follow-up

Date: 2026-08-12

This follow-up patch addresses the remaining IP-vs-MAC/stable-identity issues identified after the v24 Asset & Purdue integrity audit.

## Implemented

- Sensor assets retain multiple address bindings per MAC instead of silently collapsing every NIC to one IP.
- IP bindings are canonicalized; unspecified and multicast addresses are not accepted as asset identities.
- Authoritative ARP/NDP evidence prunes unsafe provisional routed aliases and can add multiple verified IPv4/IPv6 addresses.
- ICMPv6 Neighbor Solicitation/Advertisement link-layer options are parsed and fed into the same guarded identity-change logic as ARP.
- Detection alert dedup/approval keys include the stable asset identity; unresolved duplicate-IP claims use conflict identities so the previous owner cannot suppress the new claimant.
- Legacy communication baseline keys use authoritative MAC identity when available. During an unresolved duplicate-IP conflict, observed claimant MACs are isolated from the old owner's trusted baseline.
- Alert telemetry/history stores `asset_identity` and backfills identity from event-time binding evidence where possible.
- Central tracks `asset_ip_binding_history` as time-bounded binding episodes with `valid_from`, `valid_to`, provenance and last observation.
- Historical Asset 360 alert lookup uses identity-at-event-time rather than all-time IP aliases.
- Current duplicate-IP snapshots are represented as an explicit identity conflict. Central does not map the conflicted IP to an arbitrary MAC for operator/security ownership.
- Snapshot conflict ordering is deterministic only for display metadata; it is never used to select a stable owner.
- Provisional `ip:<address>` operator/security/recon state is promoted to an unambiguous `mac:<address>` identity when the MAC becomes known.
- Incident correlation and uniqueness are stable-identity keyed instead of IP keyed; migration 13 folds legacy duplicate open incidents while retaining incident events/comments.
- Asset-risk active alert and trend attribution uses stable identity. Flow exposure matching uses time-bounded address ownership rather than all historical aliases.
- Asset risk/history rows now carry `asset_identity`.

## Migration

Central migration **v13 — event-time asset identity and IP binding episodes** is additive/in-place. No full reset is intended.

## Validation note

All modified Go files were formatted with `gofmt`. The available build host has Go 1.23.2 while this repository requires Go 1.25.0. A package test attempt therefore required temporarily lowering the module declaration and then stalled while downloading dependencies; the repository has been restored to `go 1.25.0`. Run the normal project test/build pipeline with Go 1.25+ before production deployment.
