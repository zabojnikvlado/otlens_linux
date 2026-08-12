package detect

import "time"

// AlertType identifies the kind of anomaly/rule that fired.
type AlertType string

const (
	// AlertARPSpoof fires when an IP address's claimed MAC address
	// changes to something other than what was previously observed
	// and confirmed — the classic ARP spoofing / MITM signature.
	AlertARPSpoof AlertType = "arp_spoof"

	// AlertICSCriticalOperation fires when an ICS message is flagged
	// security-relevant by the protocol parser (e.g. S7 PLCStop,
	// PLCControl, block download) — operations that are rare and
	// high-impact in a healthy OT process regardless of any baseline.
	AlertICSCriticalOperation AlertType = "ics_critical_operation"

	// AlertNewCommunication fires when two assets are observed
	// communicating in a pattern (protocol + service) that was never
	// seen during the baseline learning window — see baseline.go.
	AlertNewCommunication AlertType = "new_communication"

	// AlertNewAsset fires when a device is discovered after baseline
	// learning completed that wasn't part of the learned device set —
	// see asset_baseline.go. The same finding also flags the device
	// itself as unconfirmed (asset.Asset.Confirmed) so the Assets tab
	// can offer a Confirm action and the topology graph can render it
	// distinctly until reviewed.
	AlertNewAsset AlertType = "new_asset"

	// AlertValueOutOfRange fires when an OT variable's value, observed
	// after baseline learning completed, falls outside the
	// [MinValue, MaxValue] range that same variable was seen to
	// occupy during learning — see store.Tag.MinValue/MaxValue and
	// core.EventValueOutOfRange.
	AlertValueOutOfRange AlertType = "value_out_of_range"

	// AlertHoneypotProbed fires when something connects TO a
	// configured deception station (config.Deception) — expected
	// behavior for a honeypot (catching reconnaissance), still a
	// useful, low-severity signal. See honeypot.go.
	AlertHoneypotProbed AlertType = "honeypot_probed"

	// AlertHoneypotLateralMovement fires when a deception station
	// itself initiates outbound traffic — should never happen from a
	// station that exists purely as a decoy, so this means it's been
	// compromised and whatever compromised it is pivoting outward.
	// See honeypot.go.
	AlertHoneypotLateralMovement AlertType = "honeypot_lateral_movement"

	// AlertExternalCommunication fires when a private/internal address
	// exchanges traffic with a public Internet unicast endpoint — see
	// handleExternalCommunication's doc comment. Direction is the initiator
	// direction of the stateful conversation (so replies to an outbound DNS/NTP
	// request do not become a second inbound alert). Findings are deduplicated
	// per internal asset, initiator direction, and bounded public-network scope.
	AlertExternalCommunication AlertType = "external_communication"

	// AlertSegmentationViolation fires when two VLANs whose configured
	// Purdue Model levels are more than the configured MaxLevelJump
	// apart communicate directly — see handleSegmentation's doc
	// comment in segmentation.go. Off unless
	// config.SensorConfig.Detect.Segmentation.Enabled and VLANLevels
	// are both configured.
	AlertSegmentationViolation AlertType = "segmentation_violation"

	// AlertReconnaissance fires when a source IP contacts an unusually
	// large number of distinct hosts (network/host scan) or distinct
	// ports on one host (port scan) within a short window — see
	// reconnaissance.go.
	AlertReconnaissance AlertType = "reconnaissance"

	// AlertC2Beacon fires when a source IP's outbound TCP connections
	// to one external destination+port happen at a suspiciously
	// regular interval — see c2beacon.go's doc comment.
	AlertC2Beacon AlertType = "c2_beacon"

	AlertMaliciousIP      AlertType = "malicious_ip"
	AlertMaliciousDomain  AlertType = "malicious_domain"
	AlertOTValueAnomaly   AlertType = "ot_value_anomaly"
	AlertLateralMovement  AlertType = "lateral_movement"
	AlertC2Correlated     AlertType = "c2_correlated"
	AlertBehaviorFinding  AlertType = "behavior_finding"
	AlertBehaviorIncident AlertType = "behavior_incident_candidate"

	// Protocol-aware product detections introduced in the hardened built-in
	// catalogue.  These have stable alert types so Central can correlate and
	// search them across product upgrades even when the human-readable rule
	// name/description evolves.
	AlertGatewayMACChanged         AlertType = "gateway_mac_changed"
	AlertDuplicateIP               AlertType = "duplicate_ip"
	AlertGratuitousARPStorm        AlertType = "gratuitous_arp_storm"
	AlertUnauthorizedOTCommand     AlertType = "unauthorized_ot_command"
	AlertControllerProgramChange   AlertType = "controller_program_change"
	AlertControllerModeChange      AlertType = "controller_mode_change"
	AlertControllerConfigChange    AlertType = "controller_configuration_change"
	AlertUnauthorizedOTWrite       AlertType = "unauthorized_ot_write"
	AlertNewEngineeringWorkstation AlertType = "new_engineering_workstation"
	AlertRemoteAdminIntoOT         AlertType = "remote_admin_into_ot"
	AlertSMBToolTransfer           AlertType = "smb_tool_transfer"
	AlertBruteForceIO              AlertType = "brute_force_io"
	AlertAssetIdentityDrift        AlertType = "asset_identity_drift"
	AlertDNSTunneling              AlertType = "dns_tunneling"
	AlertUnexpectedOTProtocol      AlertType = "unexpected_ot_protocol"
	AlertFirmwareChange            AlertType = "firmware_change"
	AlertUnauthorizedTimeChange    AlertType = "unauthorized_time_change"
	AlertProcessSequenceViolation  AlertType = "process_sequence_violation"
	AlertOTReportingLoss           AlertType = "ot_reporting_loss"
	AlertMalformedOTBurst          AlertType = "malformed_ot_burst"

	// Stable IDs advertised by docs/BUILTIN_RULE_CATALOG.md.  These are packet
	// and context policy detections rather than user-created packet rules.
	AlertFirstSeenRemoteManagement   AlertType = "first_seen_remote_management"
	AlertDirectOTProtocolAccess      AlertType = "direct_ot_protocol_access"
	AlertSMBIntoOT                   AlertType = "smb_into_ot"
	AlertUnexpectedEngineeringAccess AlertType = "unexpected_engineering_access"
	AlertLargeControllerTransfer     AlertType = "large_controller_transfer"
)

// AlertStatus is an operator's review verdict on an Alert.
type AlertStatus string

const (
	// AlertStatusNew is the default for every alert until an operator
	// reviews it.
	AlertStatusNew AlertStatus = "new"

	// AlertStatusApproved means an operator reviewed the finding and
	// decided it's expected/benign (e.g. a legitimate maintenance
	// connection that just wasn't seen during baseline learning) —
	// no further action needed, but the history is kept, not deleted.
	AlertStatusApproved AlertStatus = "approved"

	// AlertStatusConfirmed means an operator reviewed the finding and
	// confirmed it as a genuine issue — distinct from "approved" so
	// a dashboard can separate "reviewed, nothing to do" from
	// "reviewed, this needs follow-up".
	AlertStatusConfirmed AlertStatus = "confirmed"
)

// Alert is a single tracked anomaly/rule finding. Like store.Tag,
// it is deduplicated by ID: repeated occurrences of the same finding
// update Count/LastSeen on one row instead of creating a new alert
// each time, so a noisy/persistent condition doesn't flood storage.
type Alert struct {
	// ID is the dedup key for this specific finding — see the
	// detection functions for how each alert type builds it.
	ID string

	Type     AlertType
	Severity string // "low" | "medium" | "high" | "critical"
	Message  string

	IP string
	// AssetIdentity is the stable owner of IP when known. It prevents Central
	// and sensor-side approval/dedup state from following a DHCP-reused address.
	AssetIdentity string `json:"AssetIdentity,omitempty"`

	// Structured evidence for enriched detections such as threat intelligence.
	Evidence map[string]interface{} `json:"evidence,omitempty"`

	// ARP-spoofing-specific fields; empty for other alert types.
	PreviousMAC string
	NewMAC      string

	FirstSeen time.Time
	LastSeen  time.Time
	Count     uint64

	// Status is the operator's review verdict — see AlertStatus.
	// Starts at AlertStatusNew and is set explicitly wherever an
	// Alert is constructed (see arpspoof.go/icscritical.go/
	// baseline.go), since Go's zero value for a string ("") isn't
	// one of the three valid states.
	Status          AlertStatus
	StatusChangedAt time.Time

	// Synced is false whenever this alert has changed (new occurrence,
	// Count/LastSeen bump, or a Status change) since it was last
	// successfully reported to Central — see GetDirtyAlerts/
	// MarkAlertsSynced. This is what lets telemetry sync send only
	// what's actually new/changed instead of the entire alert set every
	// time; without it, a sensor that's accumulated tens of thousands
	// of distinct findings over time would re-serialize and re-upload
	// all of them on every single sync, which is both wasteful and, at
	// large enough scale, capable of exceeding PostgreSQL's per-JSONB-
	// value size limit outright.
	Synced bool

	// lastSyncTouch is runtime-only throttling state. It is deliberately
	// unexported so persistence/telemetry do not treat it as alert evidence.
	lastSyncTouch time.Time
}
