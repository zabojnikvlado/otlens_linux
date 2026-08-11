// Package netutil contains shared IP-address classification helpers used by
// sensor-side detection and risk scoring. Keeping the classification in one
// place prevents a packet from being treated as "internet" by one subsystem
// and as local/special-use traffic by another.
package netutil

import "net/netip"

var nonInternetUnicastPrefixes = []netip.Prefix{
	// IPv4 special-use ranges which netip.Addr.IsGlobalUnicast may still
	// classify as unicast, but which are not public Internet destinations.
	netip.MustParsePrefix("0.0.0.0/8"),       // current network / unspecified block
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved / limited broadcast block

	// IPv6 special-use ranges which must not be interpreted as ordinary
	// routable Internet peers.
	netip.MustParsePrefix("100::/64"),      // discard-only
	netip.MustParsePrefix("2001:10::/28"),  // ORCHID (deprecated)
	netip.MustParsePrefix("2001:20::/28"),  // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("3fff::/20"),     // documentation
}

// IsPublicInternetUnicast reports whether raw is an ordinary public unicast
// address suitable for treating as an Internet endpoint.
//
// In particular it rejects private/ULA, loopback, link-local, multicast,
// unspecified, broadcast/reserved, CGNAT, benchmarking and documentation
// ranges. This is deliberately stricter than "not private": addresses such as
// 224.0.0.22 are multicast control traffic, not Internet communication.
func IsPublicInternetUnicast(raw string) bool {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}

	for _, prefix := range nonInternetUnicastPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
