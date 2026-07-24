# Phase 3.9.5 — Durable reset and honeypot topology fix

## Root cause

The sensor reset path called `Restore(nil)` for assets, flows, OT tags and alerts. Those restore methods merged the supplied snapshot into the existing in-memory maps instead of replacing them. An empty snapshot therefore removed nothing. The following flush wrote the old PCAP-derived records back to SQLite and the next Central synchronization uploaded them again.

## Fix

- Asset, flow, OT tag and alert restore operations now replace their complete maps.
- `Restore(nil)` now reliably empties the corresponding in-memory dataset.
- Known ARP MAC state is replaced rather than merged during learning/database resets.
- SQLite snapshot flushing already clears each bucket before inserting current state, so the corrected empty engine state now removes the records from disk as intended.
- Honeypot score/classification is recomputed when assets are restored or observed again. Removing stale assets during reset prevents old non-honeypot classifications from surviving and fixes topology coloring after reset and subsequent analysis/synchronization.

This fix applies to sensor database, assets, tags, alerts, analysis and factory reset paths and therefore also makes Central telemetry/full reset durable once the queued sensor reset command is delivered.
