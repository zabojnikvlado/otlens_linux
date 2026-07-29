//go:build !linux || !cgo

package capture

import "fmt"

const MinimumLibpcapVersion = "1.10.0"

// LibpcapVersion is unavailable outside the Linux+cgo sensor build.
func LibpcapVersion() string {
	return "unavailable"
}

// ValidateLibpcapVersion explains the unsupported build instead of leaving
// cmd/otlens uncompilable on development and CI hosts.
func ValidateLibpcapVersion(string) error {
	return fmt.Errorf("pcap capture requires a Linux build with cgo enabled")
}
