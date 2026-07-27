# OTLens documentation & user manual

OTLens is a lightweight OT (operational technology) network visibility
platform: one or more headless Linux **sensors** passively watch industrial
network traffic, decode OT protocols, build an asset/topology map, and raise
alerts on suspicious activity; a single **Central** server aggregates every
sensor into one web UI, PostgreSQL-backed history, and (optionally) a SIEM
export feed.

This document is both the technical reference and the day-to-day user
manual. If you're setting OTLens up for the first time, read
[Quick start](#quick-start) through [First login](#first-login) in order.
If you're already running it, jump to [Using the Central UI](#using-the-central-ui)
or [Troubleshooting](#troubleshooting).

## Table of contents

- [Quick start](#quick-start)
- [Installing the sensor](#installing-the-sensor)
- [Installing Central](#installing-central)
- [First login](#first-login)
- [Using the Central UI](#using-the-central-ui)
- [Roles and permissions](#roles-and-permissions)
- [Configuration reference](#configuration-reference)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Build and verification](#build-and-verification)
- [Where to go next](#where-to-go-next)

---

## Quick start

Requires Go (see `go.mod` for the version), PostgreSQL reachable from
wherever Central runs, and — for live packet capture — libpcap 1.10.0+ on
the sensor host.

```bash
make build          # builds bin/otlens and bin/otlens-central for the current OS
```

Or build each target individually — see [Build and verification](#build-and-verification).

Two separate binaries, one Go module:

- `cmd/otlens` — the Linux sensor. Headless: no dashboard, no inbound HTTP
  port. It captures/decodes traffic, detects locally, stores state in
  SQLite, and pushes telemetry outbound to Central.
- `cmd/otlens-central` — the only web/API server, cross-platform (Windows or
  Linux). Serves the Central UI, receives sensor telemetry, and stores
  aggregated data in PostgreSQL.

## Installing the sensor

1. Copy `configs/sensor.config.example.yaml` to `/etc/otlens/config.yaml`
   (the sensor's built-in default path — override with `--config
   /path/to/file.yaml` if you keep it elsewhere).
2. Edit it: set `central.host`/`central.port` to point at your Central
   instance, set `central.token` to match Central's `auth.sensor_token`,
   and set `capture.interface` to the NIC to listen on (use
   `cmd/tools/interfaces` to list available interfaces if unsure).
3. Run `bin/otlens --config /etc/otlens/config.yaml`. On a production host,
   run it under systemd/a service manager so it restarts on failure and
   boot.
4. Confirm it's alive: it should appear in Central's **Sensors** tab
   shortly after starting (see [Sensors](#sensors) below).

The sensor never needs an inbound firewall rule — it only makes outbound
connections to Central's Sensor API port.

## Installing Central

1. Create a PostgreSQL database and a user with rights to it. Central
   creates every table it needs automatically on first startup — you don't
   need to run `db/central_phase3.sql` by hand (it's kept only as a
   reference snapshot of that schema).
2. Copy `configs/central.config.example.yaml` to `config.yaml` **in the
   same directory as the `otlens-central` executable itself** — that's
   where Central looks by default if you don't pass `--config` explicitly,
   on any OS (set the `OTLENS_CENTRAL_WEB_DIR` env var separately if you
   also need to relocate the UI folder — see step 6). Passing `--config
   /path/to/file.yaml` always overrides this if you'd rather keep the
   config elsewhere.
3. Fill in `database.*` (host/port/user/password/name), and set
   `auth.sensor_token` (matched by every sensor's `central.token`) and
   `auth.management_token` (an emergency/break-glass credential — see
   [Security notes](#security-notes); leave it blank to disable it
   entirely).
4. Decide the initial admin credentials: `auth.bootstrap_username`/
   `bootstrap_password` (default `administrator`/`administrator`) are used
   **once**, only if the `users` table is completely empty, to create the
   first account. Change the default password before exposing Central to
   anyone else — the account is created with a forced password change on
   first login, so the default is only ever usable for that first login.
5. Run `bin/otlens-central --config /path/to/central.config.yaml`.
6. Open `http://<central-host>:8443/ui/` (or `https://` if
   `web.tls.enabled: true`) in a browser.

Central looks for the UI files at `web/central` **relative to the
executable's own directory** by default — if you run the binary from
somewhere that doesn't have a `web/central` next to it, set the
`OTLENS_CENTRAL_WEB_DIR` environment variable to the UI's actual path
instead of relying on the default. See `deploy/systemd/README.md` for a
worked example of exactly this on Linux.

## First login

1. Log in with the bootstrap credentials (`administrator`/`administrator`
   unless you changed them in step 4 above).
2. You'll immediately be asked to set a new password — this can't be
   skipped or dismissed. Enter the current (bootstrap) password and a new
   one (minimum 8 characters).
3. From here, go to the **Users** tab to create real, named accounts for
   everyone who needs access, each with an appropriate role (see
   [Roles and permissions](#roles-and-permissions)), and consider disabling
   or at least not sharing the bootstrap `administrator` account further.

If you ever need to get back in and don't remember your password, an admin
can reset it for you from the Users tab — see [Users](#users) below. There's
no self-service "forgot password" flow (deliberately — see
[Roles and permissions](#roles-and-permissions)).

---

## Using the Central UI

The sidebar on the left has 17 tabs. Which ones you see depends on your
role (see [Roles and permissions](#roles-and-permissions)) — a tab you
can't view is simply not shown, and the same permission is enforced again
on the server, not just hidden client-side.

### Dashboard

The landing tab: sensor health at a glance (running/stopped/offline
counts), open alert count and severity breakdown, asset/OT-tag totals,
active rule coverage, PCAP analysis queue status, observed protocol mix,
baseline learning status, and the most recent backup. Every card links
through to its full tab.

### Topology

A live network map of the monitored network: nodes are discovered assets,
edges are observed connections between them. **Only private (RFC 1918)
addresses ever appear here** — a flow to/from a public internet address
never becomes a node or edge, since internet endpoints have no stable
identity to track (rotating CDN/cloud IPs) and would otherwise make the
map grow without bound. An internal asset that does talk externally is
still surfaced — as the `external_communication` alert (see
`DETECTION_RULES.md`), not a map node.

Colors/styles mean:

- **Amber dashed edge** — inter-VLAN communication (the two endpoints have
  different VLAN tags).
- **Thick red edge with an arrow** — potential lateral movement: a
  configured honeypot initiated outbound traffic **to another private
  address** (see [Setting up a honeypot](#setting-up-a-honeypot) below).
  Ordinary outbound internet traffic from the honeypot host itself
  (Windows Update, NTP, DNS, etc., if it's a real OS rather than a bare
  decoy) doesn't count as this — see the private-address note above. This
  is always worth investigating immediately.
- **Purple/highlighted node** — an asset whose score is at or above the
  configured honeypot threshold.
- **Red node** — a newly-discovered, unconfirmed asset (see
  [Assets](#assets)).

Once a connection has been observed, it stays on the map even if the
sensor's own flow tracking later ages it out (`persist.retention`,
time-based only — flow count itself has no upper bound beyond that) —
see [Architecture](#architecture) for why. A pair of assets is drawn as
**one** edge regardless of how many distinct flows (ports/sessions) exist
between them; hover an edge to see the combined flow count and traffic.
Node positions are stable across refreshes — dragging a node keeps it
there, and new assets are the only thing that triggers a brief re-layout.

A sensor only ever reports flows that are new or changed as topology
edges since its last successful sync — not its entire tracked flow set —
capped per sync, with a large backlog draining over several sync cycles
rather than all at once. Same reasoning and mechanism as
[Alerts](#alerts)' delta sync: flow count has no cap beyond time-based
retention, so a busy network can accumulate far more flows than fit in
one telemetry payload, and this is what stops that from ever exceeding
PostgreSQL's 256 MB per-JSONB-value limit.

Above the map, a row of VLAN chips (one per distinct VLAN currently on the
map, plus "Untagged") lets you toggle assets from a given VLAN on or off —
click a chip to hide/show just that VLAN, or use **All**/**None** to
reset or clear the whole map at once. This is a display filter only (it
doesn't change what Central has recorded); the choice persists across
polling refreshes and newly-discovered VLANs get their own chip
automatically.

### Assets

Every discovered device: IP, MAC, hostname, vendor, OT/IT classification,
protocols spoken, VLAN, honeypot/risk score, packet count, last-seen time.
A device discovered *after* baseline learning completes starts
**unconfirmed** (highlighted) until someone reviews and confirms it — this
is what "new_asset" alerts are about. Select rows to bulk-confirm or
bulk-delete (needs the `asset_confirm_delete` permission).

Click any row (not the checkbox) to look up known CVEs for that device's
vendor — see [Configuration reference](#configuration-reference)'s
`vulnerability` section for enabling this. Matching is vendor-only (OTLens
has no way to passively fingerprint exact firmware), so results mean
"known issues affecting this vendor," not confirmed for this specific
device. The same view also lists **every IP that device has ever been
recorded with**, oldest first — useful for a device that's changed IP
over time (DHCP renewal, static reassignment). Straight from the
`topology_nodes` ledger; the Assets tab itself only ever shows whichever
IP is currently reported.

### Devices

The same assets as the Assets tab, grouped by an automatic category
guess: **OT** (a device that's spoken a recognized OT protocol — the
same signal Assets' Class column uses, and the most reliable of the
four), **IT** (the default for anything confirmed and not otherwise
classified), **Mobile**/**Network** (vendor-name heuristics — Apple,
Samsung etc. for Mobile; Cisco, Ubiquiti, Netgear etc. for Network — a
vendor making both phone and network gear will sometimes guess wrong),
and **Rogue/Unknown** (unconfirmed, regardless of vendor). **None of
this is authoritative** — it's a starting point, not a fingerprint.

Click a device's category to correct it by hand, or use **Import asset
list** to bulk-apply corrections from a CSV (`mac,category,name` per
row, no header) — useful for seeding a whole sensor's inventory at
first deployment instead of confirming/categorizing one device at a
time. A manual or imported category always overrides the automatic
guess and persists independently of it (`asset_overrides` table) — it's
never touched by anything a sensor reports.

### Vulnerability Management

The reverse of Assets' per-device CVE lookup: every advisory in the
loaded snapshot, with the list of currently-known assets whose vendor
matches. Same vendor-only matching limitation, at larger scale — a
widely-used vendor (Siemens, Rockwell) will show *every* asset from
that vendor against *every* advisory for it, which is expected given how
approximate this matching is, not a bug. Click an advisory to see its
affected assets and the advisory link. See [Configuration
reference](#configuration-reference)'s `vulnerability` section for
loading a snapshot.

### Network Segmentation

VLAN names and Purdue Model levels, per sensor — drives the Topology
map's VLAN labels/grouping and this tab's own asset-by-segment
drill-down. **This currently only affects Central's own
naming/visualization** — the sensor's own live "Purdue Model
Segmentation Violation" detection rule (see `DETECTION_RULES.md`) still
reads its *own* `detect.segmentation.vlanlevels` from that sensor's
local config file, which editing here does not update. Keep the two in
sync by hand for now if the live rule matters to you.

Worth knowing going in: a VLAN-to-level mapping is an approximation, not
a precise boundary. An engineering workstation is conceptually Level 3
but often sits on the same physical VLAN as the Level 1 PLCs it
programs — there's no way to represent "this one device on this VLAN is
actually a different level" here yet; the whole VLAN gets one level.

### OT Tags

OT process variables (Modbus/S7 registers, etc.) the sensors have decoded,
with their current value and learned normal range. Click a tag to see its
value-change history as a chart, plus any control events (writes) recorded
against it.

### Rules

Detection rules: built-in ones (arp_spoof, new_communication,
ics_critical_operation, new_asset, value_out_of_range,
honeypot_lateral_movement/honeypot_probed — see `DETECTION_RULES.md` for
exactly how each works) plus any custom rules you add. Custom rules support
multi-condition AND/OR groups on packet fields, severity, priority,
simulation mode (log without alerting, to test a rule before it's live),
and suppression. Built-in rules can be enabled/disabled; custom rules can
be fully edited, deleted, and exported/imported as JSON (handy for copying
a rule set between sensors). Needs `rule_manage` to create/edit/delete;
viewing and exporting only needs the Rules tab's view permission.

### Alerts

Every raised alert, newest first, with severity, type, message, and the
affected IP. Select alerts to **Confirm** (acknowledge this specific
finding — a later recurrence can still alert again) or **Approve**
(remember this alert pattern on the sensor and suppress future occurrences
of the same alert ID). Needs `alert_confirm_approve`.

Backed by `alert_history` in PostgreSQL (one row per alert, upserted by
its dedup key), not the raw per-sync telemetry blob — a sensor only ever
reports alerts that are new or changed since its last successful sync
(capped per sync; a large backlog drains over several sync cycles rather
than all at once), so Central has to accumulate that into a durable
per-alert table rather than treating each sync as "here is the complete
current set." This is also what stops an OT network with a very large
number of distinct findings from ever producing a telemetry payload big
enough to hit PostgreSQL's hard 256 MB per-JSONB-value limit — the
failure mode this replaced.

**Out-of-band notifications** (`notifications` in `central.config.yaml`)
send an email and/or webhook when a new alert at or above
`min_severity` is recorded. Off by default; email is off even when
`notifications.enabled` is true (needs real SMTP settings filled in to
do anything). Independent of SIEM export — see
[Configuration reference](#configuration-reference).

### Incidents

Groups alert_history rows that share a sensor+IP and include at least
two *different* alert types within the last 24 hours — an ARP spoof
followed by a new communication pattern followed by lateral movement
against the same address, say, surfaced as one likely-related event
instead of three unrelated rows in the Alerts tab. Computed fresh from
`alert_history` on every request, not its own stored table. Same view
permission as Alerts.

### Reports

A weekly HTML summary — new assets, open alerts by severity, new
incidents, topology growth, sensor health — covering the 7 days before
each generation. Not a true PDF (no PDF library in this codebase); it's
a self-contained HTML document instead, which most email clients render
directly and which the recipient can print/save as PDF if they want one.

Configured via `reports` in `central.config.yaml`: off by default,
weekly on a configurable day/hour (UTC). Every generated report is saved
to `report_history` and viewable from the Reports tab **regardless of
whether email delivery is configured or succeeds** — so this still works
on a fully offline/air-gapped Central with no SMTP set up at all, and a
failed send doesn't lose the report. Recipients here are deliberately
separate from `notifications.email.to` (a weekly management summary and
a real-time alert ping often go to different people), but both share the
same SMTP connection settings (`notifications.email.smtp_host` etc.) —
there's no second copy of those for reports specifically.

Click **Generate now** (needs `data_management`) to produce one
immediately, covering the 7 days before that click, instead of waiting
for the next scheduled slot.

### Sensors

Every registered sensor: status (online/offline — see
[Configuration reference](#configuration-reference)'s `sensors` section for
how "offline" is detected), version info, capture backend/interface,
libpcap/Go/gopacket versions, last heartbeat/sync/data timestamps, and sync
health. Select sensors to start/stop their live capture remotely (the
sensor process and its sync link to Central stay up either way — only
packet capture pauses), or to delete them entirely. Needs `sensor_start_stop`,
which — per the default Analyst role — is the one action even a full
Analyst doesn't get; it's reserved for Admins.

Deleting a sensor removes its row and, via cascade, everything derived
from it — telemetry, topology history, alert history, analysis jobs, rule
assignments, pending commands. This is not a permanent ban: if that
sensor is still running, its next heartbeat simply recreates the row from
scratch, with fresh, empty history. Logged to the [Audit log](#audit) with
the acting username.

### Analysis

Upload a `.pcap`/`.pcapng` file to replay through a chosen sensor's full
decode/detect pipeline (useful for retroactively analyzing a capture from
somewhere else, or re-running detection after adding a new rule). The
sensor pauses live capture, processes the file, then resumes. Needs
`analysis_manage` to upload/delete; viewing the job list only needs the
Analysis tab's view permission.

### Users

Every role can open this tab — everyone needs somewhere to change their
own password. What's on it beyond that depends on `users_roles_manage`:

- **Change my password** — self-service, requires your current password.
  Visible to everyone, on any role.
- **Users table** and **Roles table** — *(admin only.)* Create/edit/
  disable/delete accounts, reset a user's password (generates a random
  temporary password shown exactly once — copy it before closing the
  dialog, it can't be retrieved again; the affected user must set a real
  password at next login, and their existing sessions are all signed out
  immediately), and edit which tabs (View) and actions (Actions) each
  role grants — including the three built-in roles' permissions (their
  `id`s just can't be deleted). Add custom roles beyond Admin/Analyst/
  View if your team needs a different split. An Analyst or View-only
  user sees only the password-change form on this tab; the tables
  themselves aren't rendered for them, and the underlying `GET /v1/users`/
  `/v1/roles` endpoints reject their requests server-side too.

### Settings

*(Admin only.)* Read-only operational status: sensor offline-detection
thresholds, whether SIEM export/PCAP analysis/vulnerability lookup are
enabled, and TLS status on both listeners. There's no write endpoint here
— change `central.config.yaml` and restart Central to actually change any
of it; this tab just lets you confirm what's running without reading the
file directly.

### Data Management

*(Admin only — `data_management`.)* Backup PostgreSQL data or queue a
selected sensor's SQLite backup; reset specific data categories (alerts,
analysis jobs, SIEM queue, rules, learning, assets/flows, OT tags, or a
full factory reset) on Central or on selected sensors. Destructive resets
require typing `RESET` to confirm. Central backups are listed with
download/delete actions.

**Central resets and sensor resets are separate things that reset
different copies of the data.** A Central-side reset (e.g. "Telemetry
database") only clears what Central has cached in PostgreSQL — it does
**not** touch the sensor's own local state, so if that sensor is still
running, its very next sync re-uploads whatever it still has locally and
the reset data reappears within one sync interval, looking like the reset
did nothing. To actually clear the underlying data, reset the sensor
itself (Sensors section of this tab) — "SQLite database" or "Assets and
flows" clears the sensor's own live engines, not just Central's copy of
them. "Telemetry database" on the Central side also clears the durable
`topology_edges`/`topology_nodes` ledger (see
[Why topology connections persist](#why-topology-connections-persist)) —
without that, the Topology tab would keep showing every previously-seen
connection regardless of any Central reset, since that ledger is
deliberately designed to survive a sensor's own pruning.

### Audit log

*(Admin only.)* Every mutating Management API request, newest first — who
did what, when, source IP, and whether it succeeded. Written
unconditionally to `audit_log`, independent of whether SIEM export is
configured (`siem.export_audit` only additionally *forwards* a copy to
SIEM — `siem.export_alerts` does the same for alerts, independently;
neither one determines whether the underlying record exists at all,
just whether it's also sent onward). Pruned by
`database_retention.audit_days`, same as everything else — see below.

Beyond the generic "method+path" entry every mutating request gets,
several actions log a specific, human-readable line instead:

- **Login / logout**, with the username.
- **Login failed**, with the attempted username (not the password,
  obviously) — logged for every failed attempt, whether the username
  didn't exist or the password was wrong (those two cases are
  deliberately indistinguishable in the response, so an attacker can't
  enumerate valid usernames, but both still show up here).
- **Brute force detected** — logged every 5th *consecutive* failed
  login for a given username (5, 10, 15, ...), reset the moment that
  username logs in successfully. Tracked in memory per username (not
  per source IP), so it survives an attacker rotating IPs but won't
  catch one IP spraying many different usernames — a different pattern
  this isn't meant to catch. This is a detection signal only; it never
  blocks or delays a login attempt.
- **Sensor went offline** — logged once per actual transition, from the
  same background sweep that drives the Sensors tab's offline status
  (`sensors.offline_after`/`check_interval`), not repeated on every sweep
  while a sensor stays down. (Deliberately no "sensor started" entry —
  with a short sensor sync interval, that would log far too often to be
  useful; the Sensors tab's own status is the place to check that.)
- **Sensor deleted**, with the sensor ID and username — see
  [Sensors](#sensors) for what this does and doesn't do.
- **Asset confirmed / deleted**, **alert confirmed / approved**, with the
  username and a summary of which targets (a short list, or a count for
  a large bulk selection — approving thousands of alerts at once
  shouldn't turn into a multi-KB audit row).
- **Rule enabled / disabled**, with the rule's name (looked up from the
  sensor's current reported rule list) alongside its ID, and the
  username.
- **Sensor capture started / stopped** (the Sensors tab action, not the
  process itself), with the username.
- **Password changed** (self-service) and **password reset by admin**,
  with the username — never the password itself.
- **User created / modified / deleted**, **role changed / deleted**,
  with the username performing the action and the target user/role.
- **Data reset** (Data Management tab, both Central and per-sensor
  scopes) and **backup created / deleted**, with the username and what
  was reset/backed up.

### Database retention

Central bounds its own PostgreSQL growth with a background sweep
(`database_retention` in `central.config.yaml`, `6h` interval by default).
It only ever touches telemetry-derived history (`topology_edges`,
`topology_nodes`, `analysis_jobs`), `alert_history` (a durable per-alert
record, separate from the live Alerts tab's `sensor_telemetry.alerts`
snapshot — see [Alerts](#alerts)), and `audit_log`. Configuration
(`rule_sets`, `sensors`, `sites`), accounts (`users`, `roles`, `sessions`),
and `system_backups` are never affected, regardless of size pressure.

Each sweep runs two passes:

1. **Age-based** — every row in those five tables older than its
   category's `*_days` cutoff (`telemetry_days`/`alerts_days`/
   `audit_days`, by last activity, not creation) is deleted, regardless
   of database size.
2. **Size backstop** — only if those same five tables' combined size is
   still over `max_database_size_gb` afterward: the globally oldest rows
   across *all five* (not a fixed per-category order — whichever table
   currently holds the single oldest row loses the next batch) are
   deleted until back at or under `target_database_size_gb`.

Both passes delete in `delete_batch_size`-row chunks with a short pause
between, so a large backlog doesn't hold a long-running lock or spike
load in one shot.

---

## Setting up a honeypot

A honeypot is just a device on your network that has no legitimate reason
to be talked to — any traffic touching it is inherently suspicious, with a
much lower false-positive rate than baseline-deviation alerts. Configure
one per sensor in `sensor.config.yaml`:

```yaml
deception:
  honeypotthreshold: 100
  stations:
    - ip: "192.168.1.99"
      score: 100
```

A station's `score` becomes that asset's `Score` once the sensor observes
traffic from/to it; `Score >= honeypotthreshold` is what marks it as a
honeypot on the map and in alerting. You can also assign a lower score
(below the threshold) to flag any asset as generally higher-priority
without making it a full honeypot — it'll show as "elevated"/"critical" in
the Assets table rather than triggering lateral-movement detection.

If the device sitting on that IP later moves off it (DHCP renewal, etc.),
its score is recomputed automatically — no restart needed — and any
still-unreviewed lateral-movement/probed alert for the old IP is cleared
automatically, since the condition that justified it no longer holds (see
[Architecture](#architecture)). Changing the `stations` list itself (adding,
removing, or repointing a decoy IP) does need a sensor restart to take
effect, since it's read once at startup.

---

## Roles and permissions

Central users authenticate with a username and password (bcrypt-hashed in
PostgreSQL, never stored in cleartext) and get a session cookie
(`otlens_session`, `HttpOnly`, `SameSite=Strict`, sent only over TLS when
`web.tls.enabled` is true) — not a token you handle directly. Sessions use
a sliding expiry (`auth.session_duration`, 6h by default): every request
pushes the expiry back out, so an active user is never logged out
mid-session, but an idle one expires that long after their last request.

Three built-in roles ship by default:

| Role | Can view | Can do |
|---|---|---|
| **Administrator** | everything | everything |
| **Analyst** | everything except Settings, Data Management, Audit (Users tab is visible to everyone, for self-service password change — see below) | everything except starting/stopping sensors |
| **View only** | Dashboard, Topology, Alerts, Users (password change only) | nothing (read-only) |

Both the tabs a role can see and the actions it can perform are stored in
PostgreSQL and fully editable from the **Users → Roles** table (admin
only) — including editing the built-in roles, though their ids can't be
deleted, and you can add entirely custom roles beyond these three. Every
API route enforces the same permission check the UI uses to decide what to
show — a hidden tab or button is a convenience, never the actual access
control, so there's no way to route around it by calling the API directly.

**Password policy:** validity (in days, or never-expiring) is set per user
when they're created and editable later. An expired-but-unchanged password
still logs in, but is immediately forced through the same change-password
flow as a brand-new account — it doesn't lock the account out. There's no
self-service "forgot password": that would need an email/SMS system this
deliberately doesn't assume (OT networks are frequently air-gapped on
purpose), so instead an admin resets a user's password from the Users tab,
which shows a random temporary password exactly once and forces a real one
to be set at next login.

`auth.management_token`, a single shared bearer token, still works as an
emergency/break-glass fallback if the session cookie is absent or invalid
— it grants full access with no per-user identity, so it's meant for
genuine operational emergencies (e.g. the `users` table or PostgreSQL
itself is unreachable), not day-to-day login. Leave it blank in
`central.config.yaml` to disable that fallback entirely.

---

## Configuration reference

Sensor and Central use **separate** config files — there is no shared
config.

- Sensor template: `configs/sensor.config.example.yaml` — default runtime
  path `/etc/otlens/config.yaml`.
- Central template: `configs/central.config.example.yaml` — default
  runtime path is `config.yaml` next to the running `otlens-central`
  executable, on any OS.

Override either with `--config /path/to/file.yaml`. Every key can also be
set via an `OTLENS_<SECTION>_<KEY>` environment variable override — see
the comments in each example file for the exact variable names.

Key sections (see the example files for full comments on every key):

**Sensor** (`sensor.config.example.yaml`):
- `capture` — interface, mode (`pcap` or `ipfix`), snaplen, promiscuous.
- `central` — host/port/token to reach Central, sync interval.
- `deception` — honeypot stations and threshold, see
  [Setting up a honeypot](#setting-up-a-honeypot).
- `detect` — detection tuning (e.g. `arpconfirmthreshold`).
- `persist` — `retention`: how long local flow/asset/alert records are
  kept before pruning (default 168h/7 days). This bounds the sensor's own
  SQLite growth; it does **not** affect what Central shows on the Topology
  tab, since Central keeps its own permanent connection ledger — see
  [Architecture](#architecture).

**Central** (`central.config.example.yaml`):
- `web` — Central UI/management API listener (default port 8443) and TLS.
- `sensor_api` — sensor telemetry/command listener (default port 9443) and
  TLS.
- `database` — PostgreSQL connection.
- `auth` — `sensor_token`, `management_token`, `session_duration`,
  `bootstrap_username`/`bootstrap_password`. See
  [Roles and permissions](#roles-and-permissions).
- `sensors` — `offline_after`/`check_interval`: how long without a
  heartbeat before a sensor shows as offline, and how often that's
  checked. Set `offline_after` to a few multiples of whatever
  `central.interval` your sensors actually use, not equal to it, so one
  slow/missed sync doesn't flap the status.
- `vulnerability` — `enabled`/`csv_path`: optional offline CVE lookup for
  the Assets tab. Prepare the CSV out of band from a public ICS advisory
  feed (see `ics_advisories.csv.example` for the expected columns:
  cve_id, vendor, product, severity, title, published_date, url) and copy
  it in like any other definition update — this is never a live network
  call.
- `siem` — optional outbound export of alerts/audit events.
- `analysis` — enable/configure PCAP upload+replay.

---

## Architecture

Two runtime roles:

1. **Linux sensor (`cmd/otlens`)** — headless. Captures via `pcap` or
   receives IPFIX, decodes OT protocols (Modbus/TCP, S7comm,
   EtherNet/IP·CIP, DNP3, OPC UA, BACnet/IP, IEC 60870-5-104, PROFINET
   DCP), builds assets/flows/topology, evaluates detection rules, persists
   local state in SQLite, and pushes telemetry outbound to Central. No
   inbound HTTP port, no dashboard, no local vulnerability browser — that
   was removed; see `docs/history/PHASE3_8_2_PROJECT_CLEANUP.md`.
2. **Central (`cmd/otlens-central`)** — the only web/API server,
   cross-platform. Serves the Central UI, receives sensor telemetry on the
   Sensor API listener, queues commands, aggregates every sensor,
   stores/aggregates data in PostgreSQL, manages rules/alerts/backups, and
   optionally exports to SIEM.

### Network listeners

Central has two independent listeners — Web/Management API (default 8443)
and Sensor API (default 9443). Sensors open no inbound port at all; they
only connect outbound to Central's Sensor API.

### Persistence

Sensors use SQLite for local resilience; Central uses PostgreSQL. Sensors
never connect directly to PostgreSQL. Sensor reset/backup commands are
delivered through the command queue over the existing sync channel — a
stopped capture engine leaves the sensor process and sync worker running
so Central can restart capture remotely.

### Why topology connections persist

A sensor prunes flows that have gone quiet (`persist.retention`, default
7 days) to bound its own SQLite growth — correct and necessary there, but
it would make a connection that only happened once disappear from the map
the moment it ages out of the sensor's live snapshot. Central avoids this
by keeping its own separate, durable, ever-growing ledger
(`topology_edges` in PostgreSQL): every telemetry sync upserts into it, and
the Topology tab reads from *that* table, not the sensor's current
snapshot. Once Central has recorded a connection, it stays on the map
regardless of what the sensor currently still reports — including a
honeypot-initiated (`FromHoneypot`) flag, which is permanent in this ledger
as a historical fact even after the device moves off the decoy IP (the
*alert* for it is cleared automatically in that case — the map annotation
isn't, see [Setting up a honeypot](#setting-up-a-honeypot)).

Assets get the same treatment (`topology_nodes`) and for the same reason:
an edge recorded in `topology_edges` is only drawable if both endpoint
assets exist as nodes, so if only edges were made durable, a connection
would still vanish the moment either endpoint asset aged out of the live
snapshot — it just wouldn't be immediately obvious *why*, since the edge
record itself was still there. Live snapshot data always wins when an
asset is present in both; the ledger only fills in for assets the current
snapshot doesn't have.

The Topology tab also draws one edge per **asset pair**, not one per
underlying flow: a sensor's raw graph has a separate flow per protocol/port
combination, so a busy pair (e.g. an HMI polling a PLC over several
sessions) could otherwise produce dozens of parallel lines between the same
two nodes. Central aggregates these server-side; the aggregated edge's
tooltip shows the flow count and combined traffic.

### Central offline-sensor detection

A background sweep (`sensors.offline_after`/`check_interval`) marks a
sensor offline once its last heartbeat goes stale — independent of
whatever status the sensor itself last reported, so a crashed or
disconnected sensor doesn't stay "online" forever.

---

## Security notes

- Bind Central's listeners only to the interfaces you actually need.
- Enable TLS (`web.tls`/`sensor_api.tls`) and use it — session cookies are
  only marked `Secure` when `web.tls.enabled` is true, so plan for TLS in
  any deployment reachable outside a fully trusted network.
- Restrict PostgreSQL to Central only; sensors never talk to it directly
  and need no inbound access at all.
- Change the bootstrap admin password immediately (the forced
  change-password flow makes this hard to skip) and create named accounts
  per person rather than sharing the bootstrap account.
- Treat `auth.management_token` as a break-glass credential, not a
  day-to-day login — see [Roles and permissions](#roles-and-permissions).
  Leave it blank if you don't have a concrete emergency-access need for it.
- The vulnerability lookup (if enabled) is a purely offline, local CSV
  match — it never makes a live network call, which matters for
  deliberately air-gapped OT networks.

---

## Troubleshooting

**A sensor never appears in the Sensors tab.**
Check the sensor's own logs first — confirm it can reach
`central.host:central.port` and that `central.token` matches Central's
`auth.sensor_token` exactly. No inbound rule is needed on the sensor side;
the connection is entirely outbound.

**A sensor shows offline but I know it's running.**
Offline status is purely heartbeat-age based (`sensors.offline_after`,
default 90s) — check the sensor's sync logs for connectivity issues, and
confirm its `central.interval` isn't longer than `offline_after` (if it
is, raise `offline_after` in `central.config.yaml` to a few multiples of
whatever sync interval your sensors actually use).

**Login succeeds but I immediately land back on the login screen.**
Open the browser's Network tab and check the `/v1/login` response for a
`Set-Cookie: otlens_session=...` header, and the very next request for a
matching `Cookie:` request header. If Set-Cookie is present but never sent
back, check for a reverse proxy stripping headers, or a browser-vs-`http://`
mismatch if `web.tls.enabled` is true but you're accessing over plain
`http://`.

**I forgot my password and can't log in.**
There's no self-service reset — ask an admin to reset it from the Users
tab (see [Roles and permissions](#roles-and-permissions)). If you're the
only admin and locked out entirely, `auth.management_token` (if
configured) can authenticate API calls directly as a break-glass path.

**Live capture won't start / sensor fails at startup.**
`capture.mode: pcap` requires libpcap **1.10.0 or newer** — the sensor
checks the linked version at startup and refuses to start capture on an
older one. Check the sensor's startup log for the detected version, or
switch to `capture.mode: ipfix` if you're receiving flow export from a
switch/router instead of capturing directly.

**Topology map is slow / feels laggy on a large network.**
This should already be addressed by Central's fingerprint-based response
caching, aggregated edges, and client-side diffing — see
[Architecture](#architecture). If it's still an issue at very large scale
(thousands of nodes), consider narrowing what you're looking at (filter to
a VLAN or a specific sensor) rather than viewing the entire network at
once.

---

## Build and verification

```bash
make fmt            # gofmt every .go file
make vet            # go vet ./...
make test            # go test ./...
make test-race        # go test -race ./...
make build-linux-sensor      # bin/otlens-linux-amd64
make build-windows-central    # bin/otlens-central-windows-amd64.exe
make build-central           # bin/otlens-central, current OS
```

## Where to go next

- **`DETECTION_RULES.md`** — how each built-in detection rule works, and
  how to add a new one (developer-oriented, in Slovak).
- **`DEPLOYMENT_WINDOWS_CENTRAL.md`** — recommended Windows Central +
  PostgreSQL + Linux sensors production topology and network policy.
- **`docs/history/`** — the phase-by-phase development log this project
  was built from. Not user-facing documentation — kept as historical
  record of *why* things ended up the way they are, in case that context
  is ever useful.
