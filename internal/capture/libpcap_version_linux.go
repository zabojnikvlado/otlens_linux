//go:build linux && cgo

package capture

/*
#cgo LDFLAGS: -lpcap
#include <pcap.h>
*/
import "C"

import (
	"fmt"
	"regexp"
	"strconv"
)

const MinimumLibpcapVersion = "1.10.0"

var libpcapVersionPattern = regexp.MustCompile(`(?i)(?:libpcap\s+version\s+)?(\d+)\.(\d+)(?:\.(\d+))?`)

// LibpcapVersion returns the full version string reported by pcap_lib_version.
func LibpcapVersion() string {
	return C.GoString(C.pcap_lib_version())
}

// ValidateLibpcapVersion rejects capture backends older than 1.10.0.
func ValidateLibpcapVersion(raw string) error {
	match := libpcapVersionPattern.FindStringSubmatch(raw)
	if len(match) == 0 {
		return fmt.Errorf("cannot determine libpcap version from %q", raw)
	}
	parts := [3]int{}
	for i := 1; i < len(match) && i <= 3; i++ {
		if match[i] == "" {
			continue
		}
		value, err := strconv.Atoi(match[i])
		if err != nil {
			return fmt.Errorf("invalid libpcap version %q: %w", raw, err)
		}
		parts[i-1] = value
	}
	if parts[0] < 1 || (parts[0] == 1 && parts[1] < 10) {
		return fmt.Errorf("unsupported libpcap version %d.%d.%d; minimum required version is %s", parts[0], parts[1], parts[2], MinimumLibpcapVersion)
	}
	return nil
}
