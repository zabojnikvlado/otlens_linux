package hostname

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28

	// maxNamePointerHops guards decodeDNSName against a malformed or
	// hostile packet with a compression pointer loop — without this,
	// a crafted packet could hang the parser in an infinite loop.
	maxNamePointerHops = 32
)

// decodeDNSName decodes a DNS wire-format name starting at offset in
// data (the full message, since compression pointers can reference
// anywhere earlier in it), returning the dotted name and the offset
// immediately after the name as it appears at the original position
// (i.e. not following into a compressed pointer's target — callers
// that need to continue parsing sequential records use this
// returned offset, not any offset reached while following pointers).
func decodeDNSName(data []byte, offset int) (string, int, error) {

	var labels []string

	startOffset := offset
	pos := offset
	hops := 0
	jumped := false

	for {

		if pos >= len(data) {
			return "", 0, fmt.Errorf("name extends past end of message")
		}

		length := int(data[pos])

		if length == 0 {
			pos++
			break
		}

		// 0xC0 high bits mark a compression pointer: 14-bit offset
		// into the message, spread across this byte and the next.
		if length&0xC0 == 0xC0 {

			if pos+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated compression pointer")
			}

			hops++

			if hops > maxNamePointerHops {
				return "", 0, fmt.Errorf("too many compression pointer hops")
			}

			pointer := int(binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3FFF)

			if !jumped {
				// First pointer we hit — the name (from the caller's
				// perspective) ends right after these 2 bytes.
				startOffset = pos + 2
				jumped = true
			}

			pos = pointer

			continue
		}

		if length > 63 {
			return "", 0, fmt.Errorf("label too long")
		}

		if pos+1+length > len(data) {
			return "", 0, fmt.Errorf("label extends past end of message")
		}

		labels = append(labels, string(data[pos+1:pos+1+length]))

		pos += 1 + length
	}

	if !jumped {
		startOffset = pos
	}

	return strings.Join(labels, "."), startOffset, nil
}

// parseMDNSHostname extracts a hostname from an mDNS (or plain DNS —
// same wire format) message, by finding the first A or AAAA record
// and taking its owner name, with a trailing ".local" (mDNS's usual
// domain suffix) stripped if present. Returns ok=false if no
// A/AAAA record was found or the message is too malformed to parse.
//
// This only looks at the record's NAME (who this address belongs
// to), not its RDATA (the address itself) — the caller pairs the
// resulting hostname with the packet's own source MAC/IP, since in
// practice an mDNS responder announces its own name.
func parseMDNSHostname(data []byte) (string, bool) {

	// Header: ID(2) Flags(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
	if len(data) < 12 {
		return "", false
	}

	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))
	nsCount := int(binary.BigEndian.Uint16(data[8:10]))
	arCount := int(binary.BigEndian.Uint16(data[10:12]))

	offset := 12

	// Skip the question section: NAME + TYPE(2) + CLASS(2) each.
	for i := 0; i < qdCount; i++ {

		_, next, err := decodeDNSName(data, offset)

		if err != nil {
			return "", false
		}

		offset = next + 4 // TYPE + CLASS

		if offset > len(data) {
			return "", false
		}
	}

	// Answers, authority, and additional records share the same
	// resource-record format; mDNS often puts the useful A/AAAA
	// record in "additional" alongside a PTR/SRV in "answers", so
	// all three sections are scanned the same way.
	totalRecords := anCount + nsCount + arCount

	for i := 0; i < totalRecords; i++ {

		name, next, err := decodeDNSName(data, offset)

		if err != nil {
			return "", false
		}

		offset = next

		// TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes, then RDATA.
		if offset+10 > len(data) {
			return "", false
		}

		recordType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))

		offset += 10

		if offset+rdLength > len(data) {
			return "", false
		}

		if recordType == dnsTypeA || recordType == dnsTypeAAAA {

			hostname := strings.TrimSuffix(strings.ToLower(name), ".local")
			hostname = strings.TrimSuffix(hostname, ".")

			if hostname != "" {
				return hostname, true
			}
		}

		offset += rdLength
	}

	return "", false
}
