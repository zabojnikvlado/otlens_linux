package parser

import (
	"encoding/binary"
	"net"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// parseNDP extracts the authoritative IPv6<->MAC pair carried by ICMPv6
// Neighbor Discovery. It intentionally handles the common Ethernet + optional
// stacked 802.1Q + IPv6-without-extension-header form; packets with extension
// headers simply remain provisional instead of being falsely trusted.
func parseNDP(frame []byte, p *core.Packet) {
	if len(frame) < 14 {
		return
	}
	off := 14
	ether := binary.BigEndian.Uint16(frame[12:14])
	for ether == 0x8100 || ether == 0x88a8 {
		if len(frame) < off+4 {
			return
		}
		ether = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	if ether != 0x86dd || len(frame) < off+40 {
		return
	}
	if frame[off+6] != 58 {
		return
	} // ICMPv6; extension-header chains stay untrusted.
	icmp := off + 40
	if len(frame) < icmp+24 {
		return
	}
	typ := frame[icmp]
	if typ != 135 && typ != 136 {
		return
	}
	src := net.IP(frame[off+8 : off+24]).String()
	target := net.IP(frame[icmp+8 : icmp+24]).String()
	opt := icmp + 24
	for opt+2 <= len(frame) {
		ot, units := frame[opt], int(frame[opt+1])
		if units == 0 {
			return
		}
		l := units * 8
		if opt+l > len(frame) {
			return
		}
		if (typ == 135 && ot == 1) || (typ == 136 && ot == 2) {
			if l >= 8 {
				mac := net.HardwareAddr(frame[opt+2 : opt+8]).String()
				if typ == 135 {
					// DAD uses :: and must not establish an address owner.
					if src != "::" {
						p.NDPSrcIP, p.NDPSrcMAC = src, mac
					}
				} else {
					p.NDPSrcIP, p.NDPSrcMAC = target, mac
				}
				return
			}
		}
		opt += l
	}
}
