# OTLens Phase 3.5.4 — PostgreSQL bootstrap fix

This release fixes Central startup against a newly-created or empty PostgreSQL database.

Previously, `OpenPostgres` attempted to create `sensor_telemetry` first. That table has a foreign key to `sensors`, so startup failed with SQLSTATE 42P01 when the base schema had not already been imported manually.

The Central binary now creates the complete schema automatically in dependency order:

1. `sites`
2. `sensors`
3. `rule_sets`
4. `sensor_rule_sets`
5. `sensor_telemetry`
6. indexes

The SQL file in `db/central_phase3.sql` remains available for manual administration, but it is no longer required for first startup.
