package hostname

import (
	"net"
)

const (
	dhcpFixedHeaderLength = 236 // op..file, before the magic cookie
	dhcpOptionHostName    = 12

	dhcpOptionEnd = 255
	dhcpOptionPad = 0
)

var dhcpMagicCookie = [4]byte{99, 130, 83, 99}

// parseDHCPHostname extracts the client's MAC (from the fixed-format
// chaddr field) and, if present, its self-reported hostname (DHCP
// option 12) from a DHCP message. The MAC comes from chaddr — not
// the packet's own Ethernet source — because DHCPDISCOVER/DHCPREQUEST
// packets are frequently sent before the client has an IP at all
// (ciaddr/source IP still 0.0.0.0), but chaddr is always populated;
// this is also why hostname.Observation is keyed by MAC, not IP.
func parseDHCPHostname(data []byte) (mac string, hostname string, ok bool) {

	if len(data) < dhcpFixedHeaderLength+4 {
		return "", "", false
	}

	// htype(1) at offset 1, hlen(1) at offset 2 — hlen is normally 6
	// for Ethernet; chaddr itself is a fixed 16-byte field starting
	// at offset 28, of which only the first hlen bytes are the
	// actual address.
	hlen := int(data[2])

	if hlen == 0 || hlen > 16 {
		return "", "", false
	}

	chaddr := data[28 : 28+hlen]

	mac = net.HardwareAddr(chaddr).String()

	cookie := data[dhcpFixedHeaderLength : dhcpFixedHeaderLength+4]

	if cookie[0] != dhcpMagicCookie[0] || cookie[1] != dhcpMagicCookie[1] ||
		cookie[2] != dhcpMagicCookie[2] || cookie[3] != dhcpMagicCookie[3] {
		// Not a well-formed DHCP options section — we at least have
		// the MAC, but no hostname to report.
		return mac, "", true
	}

	offset := dhcpFixedHeaderLength + 4

	for offset < len(data) {

		tag := data[offset]

		if tag == dhcpOptionEnd {
			break
		}

		if tag == dhcpOptionPad {
			offset++
			continue
		}

		if offset+1 >= len(data) {
			break
		}

		length := int(data[offset+1])

		valueStart := offset + 2

		if valueStart+length > len(data) {
			break
		}

		if tag == dhcpOptionHostName && length > 0 {
			hostname = string(data[valueStart : valueStart+length])
		}

		offset = valueStart + length
	}

	return mac, hostname, true
}

// isDHCPPort reports whether a UDP port pair is the standard DHCP
// client/server pair (67 = server, 68 = client) in either direction.
func isDHCPPort(srcPort, dstPort uint16) bool {
	return (srcPort == 67 || srcPort == 68) && (dstPort == 67 || dstPort == 68)
}
