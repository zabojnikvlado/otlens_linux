# Passive SMB2/SMB3 metadata parser

OTLens parses SMB2/SMB3 records observed on TCP/445. It extracts commands, session/tree/message identifiers, share names, file names, named pipes, read/write byte counts, status and artifact classifications. The parser correlates TREE_CONNECT and CREATE requests with later operations on a best-effort basis.

Lateral-movement signals include `admin_share_access`, `remote_executable_write`, `remote_script_write`, `large_smb_write`, and `suspicious_named_pipe` (including `svcctl`, `psexesvc`, `atsvc`, and `winreg`). Evidence is stored in the existing `lateral_movement_score` and `lateral_movement_confidence` fields.

Central persists observations in `smb_observations` and exposes:

`GET /v1/smb-observations?sensor_id=&client_ip=&server_ip=&artifact=&limit=`

## Limits

This is passive metadata inspection, not TCP stream reassembly. Messages split across capture packets may not decode. SMB3 transform records are marked `is_encrypted=true`; encrypted share names, file names and named pipes cannot be recovered without session keys. SMB signing does not hide metadata and remains parseable.
