// Package ipfix implements a minimal IPFIX (RFC 7011) collector: it
// listens for UDP export packets from a router/switch/probe and
// decodes them into flow records, using the sender's own Template
// Records to know how each Data Record is laid out (the same
// template-driven design NetFlow v9 uses).
//
// This is an alternative data source to internal/capture — see
// Engine's doc comment for the tradeoff. Critically: IPFIX only
// carries flow-level summaries (addresses, ports, protocol, packet/
// byte counters). It never includes packet payload or a data-link
// (MAC) layer, so anything downstream that needs those — ICS
// protocol decoding (internal/ics), ARP spoofing detection
// (internal/detect), and MAC-based asset identity (internal/asset)
// — simply has nothing to work with in IPFIX mode. capture.mode:
// ipfix trades that away for the ability to run with zero local
// capture privileges at all (no Npcap/libpcap, no admin rights
// needed — it's just a UDP listener) and to ingest flow data
// exported by network gear that's already positioned to see traffic
// OTLens itself can't directly tap into.
package ipfix

// Information Element IDs this package understands, from the IANA
// IPFIX Information Elements registry (the same numbering NetFlow v9
// uses for its overlapping fields). Only the common ones needed for
// basic flow visibility are implemented — an exporter's template can
// reference other IEs too; unrecognized ones are skipped using their
// declared length rather than causing a decode failure.
const (
	ieOctetDeltaCount          uint16 = 1
	iePacketDeltaCount         uint16 = 2
	ieProtocolIdentifier       uint16 = 4
	ieSourceTransportPort      uint16 = 7
	ieSourceIPv4Address        uint16 = 8
	ieDestinationTransportPort uint16 = 11
	ieDestinationIPv4Address   uint16 = 12
	ieSourceIPv6Address        uint16 = 27
	ieDestinationIPv6Address   uint16 = 28
)

// enterpriseBit marks a Field Specifier as vendor/enterprise-specific
// (carries an extra 4-byte Enterprise Number after the field length)
// rather than an IANA-standard Information Element.
const enterpriseBit uint16 = 0x8000

// Set ID ranges, per RFC 7011 §3.3.2.
const (
	setIDTemplate        uint16 = 2
	setIDOptionsTemplate uint16 = 3
	// Set IDs >= 256 are Data Sets, referencing a previously received
	// Template (or Options Template) by that same ID.
	minDataSetID uint16 = 256
)

// messageHeader is the fixed 16-byte IPFIX Message Header
// (RFC 7011 §3.1).
type messageHeader struct {
	Version           uint16
	Length            uint16
	ExportTime        uint32
	SequenceNumber    uint32
	ObservationDomain uint32
}

const messageHeaderLength = 16

// setHeader is the 4-byte header prefixing every Set within a
// Message (RFC 7011 §3.3.2).
type setHeader struct {
	SetID  uint16
	Length uint16
}

const setHeaderLength = 4

// fieldSpecifier is one field in a Template Record — RFC 7011 §3.4.1.
type fieldSpecifier struct {
	InformationElement uint16
	Length             uint16
	EnterpriseNumber   uint32 // only meaningful if InformationElement has enterpriseBit set
}

// template is a decoded Template Record: the field layout a later
// Data Set (referencing this template's ID) will follow.
type template struct {
	ID     uint16
	Fields []fieldSpecifier
}

// FlowRecord is one decoded IPFIX Data Record, translated into the
// handful of fields OTLens's flow tracking needs. Fields this
// package doesn't recognize in a given template are skipped (using
// their declared length) rather than causing the whole record to be
// rejected — this keeps the collector usable against exporters that
// include extra IEs beyond the common 5-tuple/counters.
type FlowRecord struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string // "TCP" / "UDP" / "ICMP" / ... — see protocolName

	// Packets/Bytes are the counters for THIS export (a delta since
	// the exporter's last report for this flow, per IPFIX semantics)
	// — not a running total. See flow.Engine.ApplyExternalDelta for
	// how these get folded into the tracked Flow.
	Packets uint64
	Bytes   uint64
}

// protocolName maps an IANA protocol number (RFC 790/the IANA
// "Assigned Internet Protocol Numbers" registry — the same numbers
// IPv4's own protocol field uses) to the short name the rest of
// OTLens already uses for L4Protocol ("TCP"/"UDP"/...).
func protocolName(n uint8) string {

	switch n {

	case 1:
		return "ICMP"

	case 6:
		return "TCP"

	case 17:
		return "UDP"

	case 58:
		return "ICMPv6"

	default:
		return "OTHER"
	}
}
