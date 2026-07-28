# Rule scopes and recommended catalogue

Detection rules now carry a `scope` field with one of `IT`, `OT`, `IT/OT`, or `Universal`.
The Rules UI provides scope/status/severity/category filters, counters, protocol metadata, and ATT&CK mappings.

Built-in detectors are classified by scope. Custom rule import/export and sensor synchronization preserve scope,
protocols, mappings, grouped conditions, suppression, simulation mode, and priority.

The Recommended rules catalogue installs conservative packet-level templates in simulation mode. Templates that
contain `CHANGE_ME_OT_VLAN` must be edited before activation. Simulation mode records matches without creating alerts,
allowing operators to tune IP/VLAN constraints and suppress expected management stations.

Deep protocol-semantic detections (for example confirmed PLC program download or a decoded write operation) remain
served by typed protocol detectors such as Critical ICS Operation rather than pretending that a port-only rule proves
the operation.
