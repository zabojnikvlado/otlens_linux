package udpconversation

import (
	"net/netip"
	"strconv"
)

// Key identifies a bidirectional UDP conversation. Endpoint A is always the
// lexicographically smaller encoded IP:port endpoint.
type Key struct {
	EndpointAIP   string
	EndpointAPort uint16
	EndpointBIP   string
	EndpointBPort uint16
}

func NewKey(aip string, aport uint16, bip string, bport uint16) Key {
	if endpointLess(bip, bport, aip, aport) {
		return Key{bip, bport, aip, aport}
	}
	return Key{aip, aport, bip, bport}
}

func endpointLess(aIP string, aPort uint16, bIP string, bPort uint16) bool {
	a, aErr := netip.ParseAddr(aIP)
	b, bErr := netip.ParseAddr(bIP)
	if aErr == nil && bErr == nil {
		if cmp := a.Compare(b); cmp != 0 {
			return cmp < 0
		}
		return aPort < bPort
	}

	// Preserve deterministic behavior for malformed/non-IP input.
	aEndpoint := aIP + ":" + strconv.FormatUint(uint64(aPort), 10)
	bEndpoint := bIP + ":" + strconv.FormatUint(uint64(bPort), 10)
	return aEndpoint < bEndpoint
}

func (k Key) isDirectionA(srcIP string, srcPort uint16) bool {
	return srcIP == k.EndpointAIP && srcPort == k.EndpointAPort
}
