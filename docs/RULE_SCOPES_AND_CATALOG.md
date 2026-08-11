# Rule catalogue and operator policy

The executable catalogue is defined by the sensor in `internal/detect/rules.go`; `docs/BUILTIN_RULE_CATALOG.md` documents the current product rules.

OTLens does **not** treat a coarse `IT`/`OT` scope label as proof that a rule is appropriate for a packet. Typed detectors use actual context instead: decoded OT protocol semantics, Central asset role/zone/Purdue metadata, learned source→target relationships, remote-management services, deception configuration, DNS/SMB observations and behavior maturity.

Built-in rules have two layers:

- **Product definition (immutable by operators):** stable ID, detector, description, protocol metadata, prerequisites and ATT&CK mapping.
- **Operator policy:** enabled state, explicit severity override or `auto`, simulation, suppression, schedule and detector parameters.

Custom packet rules retain grouped conditions and can still be imported/exported. Built-in rules cannot be deleted or replaced by a custom/rule-set payload.

The old "Recommended rules installer" is not used. The formerly documented packet templates are now executable stable built-ins, including first-seen remote management, remote management into OT, direct OT access, SMB into OT, unexpected engineering access and large controller transfer. Those relationship-heavy rules start in simulation to avoid an upgrade-time alert storm before site roles/zones are curated.
