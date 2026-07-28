# Reconnaissance UI and OT identity discovery

## Profiles

`safe-discovery` performs reverse DNS and bounded TCP/TLS/banner discovery.

`ot-conservative` adds only read-only identity exchanges and requires explicit manual approval:

- Modbus/TCP Read Device Identification (FC 43 / MEI 14)
- EtherNet/IP List Identity
- Siemens S7 ISO-on-TCP/COTP endpoint confirmation
- OPC UA Hello/Acknowledge
- Targeted BACnet/IP Who-Is/I-Am

No probe writes process values, changes controller mode, authenticates, enumerates shares, or executes commands.

## Safety controls

Every target is checked locally by the sensor against allowed networks and denied targets. Jobs have bounded probe rates, explicit protocol selection, a timeout, and a hard Central limit of 20 probes per second. OT discovery requires `require_manual_approval=true`.

## UI

The Reconnaissance tab contains Overview, Assets waiting for profiling, Jobs, and Run / policy panels. Asset rows open an explainable profile with Identity, Services, Evidence, and Recon history. Dashboard cards show profiled assets, incomplete identities, and active discovery jobs.

## Evidence

Identity values retain source and confidence. OT results are stored in `asset_recon_profile.ot_identity`; model, firmware, and serial are stored separately and surfaced through the Assets API.
