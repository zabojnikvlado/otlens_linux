package ipfix

import (
	"encoding/binary"
	"fmt"
	"net"
)

// templateStore holds every Template Record seen so far, keyed by
// (Observation Domain, Template ID) — IPFIX scopes template IDs per
// observation domain, so the same ID from two different domains (or
// two different exporters sharing a collector) must not collide.
type templateStore struct {
	templates map[string]*template
}

func newTemplateStore() *templateStore {
	return &templateStore{templates: make(map[string]*template)}
}

func templateKey(observationDomain uint32, templateID uint16) string {
	return fmt.Sprintf("%d:%d", observationDomain, templateID)
}

func (s *templateStore) get(observationDomain uint32, templateID uint16) (*template, bool) {
	t, ok := s.templates[templateKey(observationDomain, templateID)]
	return t, ok
}

func (s *templateStore) put(observationDomain uint32, t *template) {
	s.templates[templateKey(observationDomain, t.ID)] = t
}

// DecodeMessage parses one complete IPFIX Message (as received in a
// single UDP datagram — IPFIX messages are not meant to span
// multiple datagrams over UDP) and returns every FlowRecord decoded
// from its Data Sets. Template/Options Template Sets update store so
// later messages (and later Data Sets within the same message, if the
// exporter placed the template before the data — the common case)
// can be decoded; a Data Set referencing a template not yet seen is
// skipped (logged by the caller), since there's nothing to decode it
// with until that template arrives.
func DecodeMessage(data []byte, store *templateStore) ([]FlowRecord, error) {

	if len(data) < messageHeaderLength {
		return nil, fmt.Errorf("message too short for header: %d bytes", len(data))
	}

	header := messageHeader{
		Version:           binary.BigEndian.Uint16(data[0:2]),
		Length:            binary.BigEndian.Uint16(data[2:4]),
		ExportTime:        binary.BigEndian.Uint32(data[4:8]),
		SequenceNumber:    binary.BigEndian.Uint32(data[8:12]),
		ObservationDomain: binary.BigEndian.Uint32(data[12:16]),
	}

	if header.Version != 10 {
		return nil, fmt.Errorf("unsupported IPFIX version %d (expected 10)", header.Version)
	}

	msgLen := int(header.Length)

	if msgLen > len(data) {
		msgLen = len(data) // be lenient: some exporters miscount padding
	}

	var records []FlowRecord

	offset := messageHeaderLength

	for offset+setHeaderLength <= msgLen {

		set := setHeader{
			SetID:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Length: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}

		setEnd := offset + int(set.Length)

		if set.Length < setHeaderLength || setEnd > msgLen {
			// Malformed/truncated set — stop rather than risk reading
			// garbage as if it were the next set header.
			break
		}

		body := data[offset+setHeaderLength : setEnd]

		switch {

		case set.SetID == setIDTemplate || set.SetID == setIDOptionsTemplate:
			decodeTemplateSet(body, header.ObservationDomain, store)

		case set.SetID >= minDataSetID:

			if t, ok := store.get(header.ObservationDomain, set.SetID); ok {
				records = append(records, decodeDataSet(body, t)...)
			}
			// No else: a Data Set for a template we haven't seen yet
			// is silently skipped — see doc comment above.

		}

		offset = setEnd
	}

	return records, nil
}

// decodeTemplateSet parses one or more Template Records out of a
// Template Set's body and stores each one.
func decodeTemplateSet(body []byte, observationDomain uint32, store *templateStore) {

	offset := 0

	for offset+4 <= len(body) {

		templateID := binary.BigEndian.Uint16(body[offset : offset+2])
		fieldCount := binary.BigEndian.Uint16(body[offset+2 : offset+4])
		offset += 4

		fields := make([]fieldSpecifier, 0, fieldCount)

		for i := 0; i < int(fieldCount); i++ {

			if offset+4 > len(body) {
				return // truncated — stop, keep whatever we decoded so far
			}

			rawIE := binary.BigEndian.Uint16(body[offset : offset+2])
			length := binary.BigEndian.Uint16(body[offset+2 : offset+4])
			offset += 4

			field := fieldSpecifier{
				InformationElement: rawIE &^ enterpriseBit,
				Length:             length,
			}

			if rawIE&enterpriseBit != 0 {

				if offset+4 > len(body) {
					return
				}

				field.EnterpriseNumber = binary.BigEndian.Uint32(body[offset : offset+4])
				offset += 4
			}

			fields = append(fields, field)
		}

		store.put(observationDomain, &template{ID: templateID, Fields: fields})
	}
}

// decodeDataSet parses every Data Record in a Data Set's body
// according to t's field layout, extracting the handful of
// Information Elements FlowRecord understands and skipping the rest
// by their declared length.
func decodeDataSet(body []byte, t *template) []FlowRecord {

	recordLength := 0

	for _, f := range t.Fields {
		recordLength += int(f.Length)
	}

	if recordLength == 0 {
		return nil
	}

	var records []FlowRecord

	offset := 0

	for offset+recordLength <= len(body) {

		record := body[offset : offset+recordLength]
		records = append(records, decodeRecord(record, t.Fields))
		offset += recordLength
	}

	return records
}

func decodeRecord(record []byte, fields []fieldSpecifier) FlowRecord {

	var fr FlowRecord

	offset := 0

	for _, f := range fields {

		length := int(f.Length)

		if offset+length > len(record) {
			break // truncated record — return whatever was decoded so far
		}

		value := record[offset : offset+length]

		switch f.InformationElement {

		case ieSourceIPv4Address:
			if length == 4 {
				fr.SrcIP = net.IP(value).String()
			}

		case ieDestinationIPv4Address:
			if length == 4 {
				fr.DstIP = net.IP(value).String()
			}

		case ieSourceIPv6Address:
			if length == 16 {
				fr.SrcIP = net.IP(value).String()
			}

		case ieDestinationIPv6Address:
			if length == 16 {
				fr.DstIP = net.IP(value).String()
			}

		case ieSourceTransportPort:
			fr.SrcPort = decodeUint16(value)

		case ieDestinationTransportPort:
			fr.DstPort = decodeUint16(value)

		case ieProtocolIdentifier:
			if length >= 1 {
				fr.Protocol = protocolName(value[0])
			}

		case iePacketDeltaCount:
			fr.Packets = decodeUint64(value)

		case ieOctetDeltaCount:
			fr.Bytes = decodeUint64(value)

		}

		offset += length
	}

	return fr
}

// decodeUint16/decodeUint64 read a big-endian integer of whatever
// width the field actually declared (IPFIX allows narrower encodings
// than the IE's "natural" width, e.g. a port sometimes sent in fewer
// than 2 bytes is not typical, but counters are very often sent as
// 4 bytes instead of a full 8) — padding on the left with zero bytes
// covers any width up to the destination type's size.
func decodeUint16(b []byte) uint16 {

	var buf [2]byte

	if len(b) > 2 {
		b = b[len(b)-2:]
	}

	copy(buf[2-len(b):], b)

	return binary.BigEndian.Uint16(buf[:])
}

func decodeUint64(b []byte) uint64 {

	var buf [8]byte

	if len(b) > 8 {
		b = b[len(b)-8:]
	}

	copy(buf[8-len(b):], b)

	return binary.BigEndian.Uint64(buf[:])
}
