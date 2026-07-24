# Phase 3.6.8 — Topology stability fix

## Problem

Topology nodes could visibly tremble after the graph had already settled. Central refreshes telemetry every 10 seconds. The previous renderer preserved coordinates, but also explicitly set every node to `fixed: false` while the vis-network physics solver remained enabled. Each DataSet refresh therefore reintroduced small force calculations and visible movement.

## Behaviour after the fix

- The initial topology performs one stabilization pass.
- Physics is disabled immediately after stabilization.
- Regular telemetry refreshes update labels, colours, scores, alerts and edges without touching node coordinates.
- Positions selected by the operator through drag-and-drop remain unchanged.
- When a genuinely new asset appears, existing nodes are temporarily fixed and only the new node participates in a short stabilization pass.
- Physics is disabled again after that pass.
- Removed nodes and updated edges do not restart layout calculation.

This eliminates periodic trembling while still allowing newly discovered assets to be placed automatically.
