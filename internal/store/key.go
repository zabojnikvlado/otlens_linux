package store

import "fmt"

// BuildKey builds the dedup identity for a Tag from the fields that
// define "the same variable" — protocol, device, unit, and address.
// Two polls of the same register always produce the same key, which
// is what lets the (not-yet-implemented) Engine update a single Tag
// row in place instead of appending a new one per poll.
//
// Deliberately excluded from the key: value, timestamp, and which
// side of the conversation initiated the request — those belong on
// the Tag/ValueChange/ControlEvent records, not the identity.
func BuildKey(
	protocol string,
	deviceIP string,
	devicePort uint16,
	unitID uint8,
	addressSpace string,
	address uint32,
) string {

	return fmt.Sprintf(
		"%s|%s:%d|%d|%s|%d",
		protocol,
		deviceIP,
		devicePort,
		unitID,
		addressSpace,
		address,
	)
}
