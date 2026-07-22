// Package hostname discovers device hostnames from traffic that
// happens to announce them — mDNS (dns.go) and DHCP (dhcp.go) — since
// neither is available from packet headers alone the way IP/MAC are.
// Observations are published as core.EventHostnameSeen rather than
// written directly into internal/asset's data, keeping with the rest
// of OTLens's event-bus-only communication between engines: this
// package only knows how to parse two wire formats, not how asset
// records are stored.
package hostname

// Observation is one MAC-to-hostname mapping learned from the wire.
type Observation struct {
	MAC      string
	Hostname string

	// Source records which protocol produced this, e.g. "mDNS" or
	// "DHCP" — useful for debugging/display, not used for any logic.
	Source string
}
