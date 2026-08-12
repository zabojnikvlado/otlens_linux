# OTLens — SMB visibility & Explorer fix

Date: 2026-08-12

## Symptoms

- Central raises `New SMB communication` / remote-management alerts for TCP/445, but the same client/server pair is absent from SMB Explorer.
- Searching SMB Explorer by IP/text can return `SMB load failed`.
- Large retained SMB history makes the Explorer slow to open.

The observed example was `10.1.107.156 -> 10.1.222.128:445`.

## Root causes

### 1. Detection and SMB Explorer used different evidence levels

The first-seen SMB/remote-management detection is intentionally transport-level: a TCP SYN to destination port 445 is enough to prove an SMB transport relationship.

SMB Explorer, however, only returned rows emitted by the SMB2/SMB3 application decoder. A TCP/445 relationship therefore disappeared from the Explorer when payload decoding was unavailable, even though the flow and alert layers had already seen it.

Common cases are:

- capture started after the SMB session was already established;
- SMB3 encryption is already active;
- TCP reassembly has a gap;
- only a partial stream is visible at the sensor;
- SMB1/unsupported application framing is present.

### 2. Mid-stream SMB framing could become poisoned

The stream parser previously accepted any zero byte as the beginning of a possible NBSS header and trusted the following 24-bit length before validating that the payload actually started with `FE SMB` or `FD SMB`.

Arbitrary encrypted bytes can contain such a sequence. The parser could then wait for a bogus multi-megabyte frame and never reach the next real SMB record.

### 3. SMB search had an invalid PostgreSQL predicate

`smb_observations.status` is a `BIGINT`, but the search predicate used:

`status ILIKE ...`

When the user supplied a non-empty SMB search string, PostgreSQL could reject the query with an operator type error. The query now uses `status::text ILIKE ...`.

### 4. Explorer reads were not indexed for the actual access pattern

The previous query used `($param='' OR column=$param)` predicates and had no standalone newest-first `observed_at` index. This makes a large retained SMB table unnecessarily expensive to search and sort.

## Fixes

### Sensor

- SMB stream framing now validates the NBSS header together with the SMB2/SMB3 signature before trusting the frame length.
- Mid-stream and gapped streams actively resynchronize to a real `FE SMB` / `FD SMB` frame.
- Invalid ciphertext bytes can no longer poison the parser by creating a plausible fake length.
- Added regression tests for mid-stream resynchronization and encrypted SMB3 transform visibility.

### Central API

- SMB decoded-observation query uses dynamic predicates instead of optional-parameter OR expressions.
- Numeric `status` search is cast safely to text.
- Optional `include_transport=true` adds TCP/445 evidence from `flow_observations` when no decoded SMB evidence exists for the same relationship/lifetime.
- Transport rows are explicitly marked `evidence_source=transport` and `command=transport_session`; they are not presented as decoded SMB commands.

### Web UI

SMB Explorer now requests transport fallback evidence and shows:

- `Decoded SMB` for application-decoded records;
- `Transport` / `TRANSPORT ONLY` for a confirmed TCP/445 relationship without safe SMB payload decoding.

The count separates decoded and transport-only evidence. API failures now expose the returned error text in the page instead of only showing the generic `SMB load failed` message.

### Database migration v16

Adds read indexes:

- `idx_smb_observations_time_desc`
- `idx_smb_observations_client_time`
- `idx_smb_observations_server_time`
- partial `idx_flow_observations_smb_transport` for TCP/445 flow evidence

No database reset is required.

## Expected result for the reported connection

If Central has retained flow evidence for `10.1.107.156 -> 10.1.222.128:445`, searching SMB Explorer for either IP will now show the relationship even if the SMB application decoder could not reconstruct a command. Such a row is intentionally labelled `Transport / TCP/445 session / TRANSPORT ONLY`.

If SMB2/SMB3 records are decoded, the Explorer continues to show the richer command/share/file/encryption records instead of adding a duplicate transport row.

## Validation performed

- `go test ./internal/smb` passes, including new mid-stream/encrypted-frame regression tests.
- All Go source files parse successfully with the Go parser.
- All production Central JavaScript files pass `node --check`.
- Full `go test ./internal/central` could not be completed in the execution environment because uncached external Go modules could not be downloaded before timeout.
