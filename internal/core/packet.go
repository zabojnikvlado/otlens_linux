package core

import "time"

// Packet is the fully-decoded result of parsing one captured frame —
// see internal/parser. Not every field is populated for every
// packet: which ones are set depends on which layers were actually
// present (e.g. ARP* fields are only set for ARP packets, TCP*
// fields only for TCP). PacketType reflects the L3 identity
// (Ethernet/IPv4/IPv6/ARP); L4Protocol reflects the transport
// (TCP/UDP/ARP) — see internal/parser/parser.go for why these are
// kept as two separate fields rather than one.
type Packet struct {
	// Ethernet (L2)
	SrcMAC string
	DstMAC string

	// VLANID is the 802.1Q VLAN tag, if present; 0 otherwise.
	VLANID uint16

	// IP (L3) — populated for both IPv4 and IPv6, so downstream
	// consumers (flow, asset, detect...) don't need to care which
	// version a given packet used.
	SrcIP string
	DstIP string

	TTL            uint8  // IPv4 TTL, or IPv6 hop limit
	IPProtocol     string // IPv4 protocol, or IPv6 next header
	IPFlags        string // IPv4 fragmentation flags (DF/MF); empty for IPv6
	IPHeaderLength int    // IPv4 header length in bytes; unset for IPv6

	// Transport (L4)
	SrcPort uint16
	DstPort uint16

	TCPFlags  string // e.g. "SYN", "SYN,ACK" — see parser/tcp.go
	TCPSeq    uint32
	TCPAck    uint32
	TCPWindow uint16

	UDPLength uint16

	// ARP — the claimed MAC/IP mapping, used by detect's ARP
	// spoofing check. Only set for ARP packets.
	ARPOperation string // "Request" or "Reply"
	ARPSrcMAC    string
	ARPSrcIP     string
	ARPDstMAC    string
	ARPDstIP     string

	EtherType  string // e.g. "IPv4", "ARP" — from the Ethernet header
	L4Protocol string // "TCP", "UDP", or "ARP"

	PacketType string // "Ethernet", "IPv4", "IPv6", or "ARP" — see doc comment above

	Length int // total captured frame length in bytes

	// Timestamp is when this packet was captured (from the original
	// RawFrame — see its doc comment for why this isn't just
	// time.Now()).
	Timestamp time.Time

	// FromAnalysis — see RawFrame's doc comment. Propagated straight
	// through by internal/parser.
	FromAnalysis bool

	// AppPayload holds the application-layer bytes (i.e. whatever
	// comes after the TCP/UDP header) so protocol parsers (Modbus,
	// S7comm...) can decode it without re-parsing the whole frame.
	// Deliberately not the whole raw frame — see internal/parser
	// and internal/ics for why we keep this lean.
	AppPayload []byte
}
