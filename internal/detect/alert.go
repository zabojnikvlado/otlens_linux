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
}
