# Built-in rule catalogue

OTLens ships product-managed built-in rules classified as IT, OT, IT/OT and Universal.

The former Recommended Rules installer was removed. The six packet-policy templates are now built-ins with stable IDs:

- `builtin.first_seen_remote_management`
- `builtin.remote_management_into_ot`
- `builtin.direct_ot_protocol_access`
- `builtin.smb_into_ot`
- `builtin.unexpected_engineering_access`
- `builtin.large_controller_transfer`

They start in simulation mode because VLANs and approved engineering sources are environment-specific. Built-ins cannot be deleted. Operator-controlled enabled state, severity, simulation mode, suppression and schedule are preserved when managed rules are restored, while the product definition and metadata remain upgrade-controlled.

Built-ins that contain packet condition groups are evaluated by the packet-policy engine in the same way as custom packet rules. Typed built-ins continue to be evaluated by their protocol-aware detectors.
