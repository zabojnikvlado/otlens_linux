// Package flow tracks network conversations (flows) between two
// endpoints, folding both directions of traffic into a single
// bidirectional record — see engine.go's flowKey.
package flow

import "time"

// Flow is one tracked conversation between two IP:port endpoints
// over a given L4 protocol. Both directions of the conversation
// (A->B and B->A packets) update the same Flow — see flowKey in
// engine.go for how that's keyed.
type Flow struct {
	// ID is the direction-independent dedup key — see flowKey.
	ID string

	// SrcIP/DstIP/SrcPort/DstPort reflect whichever direction was
	// observed *first*; because the key folds both directions
	// together, don't rely on these to determine "who initiated" —
	// they're just one arbitrary snapshot of the endpoint pair.
	SrcIP string
	DstIP string

	SrcPort uint16
	DstPort uint16

	Protocol string // L4 protocol, e.g. "TCP" or "UDP"

	// Initiator/Responder are stable conversation roles. For TCP the initiator
	// is learned from the first SYN without ACK; for UDP/IPFIX they default to
	// the first observed/exported direction. Directional counters always use
	// these roles, independent of SrcIP/DstIP legacy fields.
	InitiatorIP   string
	ResponderIP   string
	InitiatorPort uint16
	ResponderPort uint16
	PacketsAToB   uint64
	PacketsBToA   uint64
	BytesAToB     uint64
	BytesBToA     uint64

	// Packets/Bytes accumulate across every packet seen in either
	// direction since FirstSeen.
	Packets uint64
	Bytes   uint64

	FirstSeen time.Time
	LastSeen  time.Time

	// FromAnalysis — see asset.Asset's field of the same name for the
	// full explanation. Same semantics: true only while this flow has
	// never been confirmed by live (or IPFIX) traffic, exempting it
	// from age-based retention pruning.
	FromAnalysis bool

	// HoneypotInitiated is true once ANY packet in this flow's
	// lifetime had a configured deception station (config.Deception)
	// as its source — checked per-packet in Update, deliberately NOT
	// derived from SrcIP/DstIP above, for exactly the reason those
	// fields' doc comment warns about: this flow folds both
	// directions of the conversation together, so "the honeypot sent
	// something on this pair, at some point" can't be recovered from
	// whichever single packet happened to create the record first.
	// Sticky once set — a flow that's ever seen honeypot-initiated
	// traffic stays flagged for its lifetime, even if later packets
	// go the other direction. Drives topology.Edge.FromHoneypot.
	HoneypotInitiated bool

	// VLANID is the 802.1Q VLAN tag most recently observed for this
	// conversation — 0 means untagged. Drives the Topology tab's
	// VLAN filter — see topology.Edge.VLANID.
	VLANID uint16

	// Synced is false whenever this flow has changed (new, or
	// Packets/Bytes/LastSeen bumped) since it was last successfully
	// reported to Central — see Engine.GetDirtyFlows/MarkFlowsSynced.
	// Same reasoning as detect.Alert.Synced: without this, telemetry
	// would re-serialize and re-upload *every* tracked flow as a
	// topology edge on every single sync, and unlike alerts (which
	// have delta-sync already), flows have no size cap at all beyond
	// persist.retention's time-based pruning — a busy network can
	// accumulate far more of these than fit in one JSONB value.
	Synced bool
}

// SyncSnapshot is the subset of a flow serialized into Central telemetry that
// must still match before an ACK is allowed to mark the live flow synchronized.
// It prevents an in-flight HTTP request from acknowledging a newer local flow
// version that Central never received.
type SyncSnapshot struct {
	ID            string
	InitiatorIP   string
	ResponderIP   string
	InitiatorPort uint16
	ResponderPort uint16
	PacketsAToB   uint64
	PacketsBToA   uint64
	BytesAToB     uint64
	BytesBToA     uint64
	Packets       uint64
	Bytes         uint64
	LastSeen      time.Time
	VLANID        uint16
}
