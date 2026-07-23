package ics

import (
	"encoding/binary"
	"fmt"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// S7comm rides on top of ISO-on-TCP (RFC 1006): TPKT header, then a
// COTP (ISO 8073) header, then — only for COTP "Data" TPDUs — the S7
// header itself. Reference: Siemens S7 protocol as reverse-engineered
// by the Wireshark/snap7 projects; there is no official public spec.

const (
	cotpPDUTypeData           uint8 = 0xF0 // DT (Data) TPDU — carries the S7 payload
	cotpPDUTypeConnectRequest uint8 = 0xE0
	cotpPDUTypeConnectConfirm uint8 = 0xD0
	cotpPDUTypeDisconnectReq  uint8 = 0x80
	s7ProtocolID              uint8 = 0x32 // fixed magic byte identifying S7comm
)

// s7ROSCTRNames maps the S7 "ROSCTR" (Remote Operation Service
// Control) byte to a readable message class.
var s7ROSCTRNames = map[uint8]string{
	0x01: "Job",      // request, e.g. read/write var, PLC control
	0x02: "Ack",      // acknowledge, no data
	0x03: "AckData",  // acknowledge carrying response data
	0x07: "UserData", // vendor-specific extensions (e.g. NetPro diagnostics)
}

// s7FunctionNames maps the S7 parameter-block function code (the
// first byte of the parameter section) to a readable name. This is
// the field that matters most for OT security monitoring: reads and
// writes are routine, but PLC Control / PLC Stop are the classic
// signature of an attacker (or a careless engineer) trying to halt a
// controller — e.g. the well-known "STOP CPU" attack primitive.
var s7FunctionNames = map[uint8]string{
	0x04: "ReadVar",
	0x05: "WriteVar",
	0x1A: "RequestDownload",
	0x1B: "DownloadBlock",
	0x1C: "DownloadEnded",
	0x1D: "StartUpload",
	0x1E: "Upload",
	0x1F: "EndUpload",
	0x28: "PLCControl", // start / warm restart / insert block, sub-function distinguishes
	0x29: "PLCStop",    // stop CPU — high-value alert regardless of context
	0xF0: "SetupCommunication",
}

// s7CriticalFunctions are function codes that should be treated as
// security-relevant events on their own — independent of any
// baselining/anomaly logic — because in a healthy OT environment
// they are rare and their impact (halting or reprogramming a
// controller) is high.
var s7CriticalFunctions = map[uint8]bool{
	0x28: true, // PLCControl
	0x29: true, // PLCStop
	0x1A: true, // RequestDownload (reprogramming)
	0x1B: true, // DownloadBlock
}

func s7FunctionName(fc uint8) string {

	if name, ok := s7FunctionNames[fc]; ok {
		return name
	}

	return fmt.Sprintf("Unknown(0x%02X)", fc)
}

// s7ItemAddress is one decoded "S7ANY" variable specification from a
// ReadVar/WriteVar parameter block.
type s7ItemAddress struct {
	area          string // "I", "Q", "M", "DB", "C", "T"
	dbNumber      uint16 // only meaningful when area == "DB"
	bitAddress    uint32 // raw wire bit-address (byte offset*8 + bit offset)
	transportSize uint8
}

// parseS7FirstItemAddress decodes the FIRST item's S7ANY address
// specification from a ReadVar/WriteVar parameter block (param[0] is
// the function code, param[1] the item count, param[2:] the item
// list). Only the "S7ANY" addressing syntax (syntax ID 0x10) is
// understood — by far the most common addressing mode in real S7
// traffic, but S7-1200/1500 controllers can also use symbolic/
// optimized addressing (a different syntax ID), which isn't decoded
// here and simply falls through to ok=false, same as any other
// unrecognized format.
//
// Only the first item is decoded — a single ReadVar/WriteVar message
// can address multiple variables at once, but each additional item
// needs its own area/DB/address triplet tracked separately (unlike
// Modbus's WriteMultipleRegisters, where a multi-item read/write is
// just sequential register addresses — see
// store.expandAddressRange), which isn't implemented yet.
func parseS7FirstItemAddress(param []byte) (s7ItemAddress, bool) {

	if len(param) < 2 {
		return s7ItemAddress{}, false
	}

	if param[1] == 0 {
		// Item count is 0 — nothing addressed.
		return s7ItemAddress{}, false
	}

	item := param[2:]

	// Fixed S7ANY item layout: variable spec type(1)=0x12,
	// address-spec length(1)=0x0A, syntax ID(1)=0x10, transport
	// size(1), count(2), DB number(2), area(1), address(3) = 12
	// bytes total.
	if len(item) < 12 {
		return s7ItemAddress{}, false
	}

	if item[0] != 0x12 || item[2] != 0x10 {
		// Not a plain S7ANY item (variable spec type / syntax ID
		// mismatch) — likely symbolic/optimized addressing, which
		// isn't decoded here.
		return s7ItemAddress{}, false
	}

	transportSize := item[3]
	dbNumber := binary.BigEndian.Uint16(item[6:8])
	areaByte := item[8]

	bitAddress := uint32(item[9])<<16 | uint32(item[10])<<8 | uint32(item[11])

	var area string

	switch areaByte {
	case 0x81:
		area = "I"
	case 0x82:
		area = "Q"
	case 0x83:
		area = "M"
	case 0x84:
		area = "DB"
	case 0x1C:
		area = "C"
	case 0x1D:
		area = "T"
	default:
		return s7ItemAddress{}, false
	}

	return s7ItemAddress{
		area:          area,
		dbNumber:      dbNumber,
		bitAddress:    bitAddress,
		transportSize: transportSize,
	}, true
}

// parseS7FirstItemValue decodes the FIRST item's data record from a
// ReadVar response's or WriteVar request's DATA section: return
// code(1), transport size(1), length(2), then the raw value bytes.
//
// S7comm has no official public specification — this wire format,
// including which of "length in bits" vs "length in bytes" applies
// for a given transport size byte, is reverse-engineered community
// knowledge (Wireshark's s7comm dissector, python-snap7), not from a
// spec Siemens publishes. Treat this as best-effort: it correctly
// covers the overwhelming common case (single BOOL/BYTE/WORD/DWORD
// value), but an exotic/rare transport size could decode wrong
// rather than not at all.
func parseS7FirstItemValue(data []byte) (value any, ok bool) {

	if len(data) < 4 {
		return nil, false
	}

	returnCode := data[0]

	if returnCode != 0xFF {
		// Anything other than "success" (e.g. 0x0A "object does not
		// exist") means there's no real value here to report.
		return nil, false
	}

	transportSize := data[1]
	lengthField := binary.BigEndian.Uint16(data[2:4])

	payload := data[4:]

	if transportSize == 0x03 {

		// BIT — length field is a bit count; every ReadVar/WriteVar
		// item actually used in practice is a single bit, which is
		// all this handles.
		if len(payload) < 1 {
			return nil, false
		}

		return payload[0]&0x01 != 0, true
	}

	// BYTE/WORD/DWORD/REAL and similar — length field is a byte
	// count.
	byteLen := int(lengthField)

	if byteLen > len(payload) {
		byteLen = len(payload)
	}

	switch {

	case byteLen == 1:
		return payload[0], true

	case byteLen == 2:
		return binary.BigEndian.Uint16(payload[0:2]), true

	case byteLen >= 4:
		return binary.BigEndian.Uint32(payload[0:4]), true

	default:
		return nil, false
	}
}

// parseS7Comm decodes TPKT + COTP + S7 headers from a TCP payload on
// port 102. Only COTP "Data" TPDUs carrying a valid S7 magic byte
// are treated as S7comm messages; COTP connection setup/teardown
// TPDUs (CR/CC/DR) are recognized structurally but intentionally not
// decoded further here — they carry no ROSCTR/function code and
// tracking the TSAP negotiation they contain (which identifies the
// PLC rack/slot being addressed) is left as future work once the
// storage layer for connection state exists.
func parseS7Comm(packet core.Packet) (Message, bool) {

	data := packet.AppPayload

	// TPKT header is a fixed 4 bytes: version(1), reserved(1), length(2).
	if len(data) < 4 {
		return Message{}, false
	}

	if data[0] != 3 {
		// TPKT version is always 3 for RFC 1006 — cheap sanity check.
		return Message{}, false
	}

	tpktLength := binary.BigEndian.Uint16(data[2:4])

	if int(tpktLength) > len(data) {
		return Message{}, false
	}

	cotp := data[4:]

	// COTP: length indicator (1 byte) + PDU type byte, at minimum.
	if len(cotp) < 2 {
		return Message{}, false
	}

	liLength := int(cotp[0])
	pduType := cotp[1] & 0xF0

	switch pduType {

	case cotpPDUTypeConnectRequest, cotpPDUTypeConnectConfirm, cotpPDUTypeDisconnectReq:

		// Connection management, not an application-layer S7
		// message — not decoded further (see doc comment above).
		return Message{}, false

	case cotpPDUTypeData:

		// DT TPDU header: length indicator byte + PDU type/credit
		// byte + TPDU-NR/EOT byte = liLength+1 bytes total.
		headerEnd := 1 + liLength

		if headerEnd >= len(cotp) {
			return Message{}, false
		}

		return parseS7Header(packet, cotp[headerEnd:])

	default:
		return Message{}, false
	}
}

// parseS7Header decodes the S7 protocol header and, where present,
// the function code from the parameter block.
func parseS7Header(packet core.Packet, s7 []byte) (Message, bool) {

	// Fixed part: protocol ID(1), ROSCTR(1), redundancy ID(2),
	// PDU reference(2), parameter length(2), data length(2) = 10 bytes.
	// AckData messages add error class(1) + error code(1) = 12 bytes.
	if len(s7) < 10 {
		return Message{}, false
	}

	if s7[0] != s7ProtocolID {
		return Message{}, false
	}

	rosctr := s7[1]

	headerLen := 10

	if rosctr == 0x03 { // AckData carries an extra error class/code
		headerLen = 12
	}

	if len(s7) < headerLen {
		return Message{}, false
	}

	pduReference := binary.BigEndian.Uint16(s7[4:6])
	paramLength := binary.BigEndian.Uint16(s7[6:8])
	dataLength := binary.BigEndian.Uint16(s7[8:10])

	msg := newMessage(packet, "S7comm")

	msg.Details["rosctr"] = s7ROSCTRNames[rosctr]
	msg.Details["pdu_reference"] = pduReference
	msg.IsResponse = rosctr == 0x02 || rosctr == 0x03

	if paramLength == 0 || len(s7) < headerLen+int(paramLength) {
		// No parameter block (e.g. bare Ack) — still a valid,
		// if uninformative, S7comm message.
		return msg, true
	}

	param := s7[headerLen : headerLen+int(paramLength)]

	fc := param[0]

	msg.FunctionCode = fc
	msg.FunctionName = s7FunctionName(fc)

	if s7CriticalFunctions[fc] {
		msg.Details["security_relevant"] = true
	}

	// Item-level address/value — only for ReadVar/WriteVar Job
	// (request) messages. A response's parameter block doesn't repeat
	// the address (only the original request carries it), so without
	// request/response correlation (not implemented — see
	// DOCUMENTATION.md's known limitations) a response's decoded
	// value has nothing to attach an address to and gets left alone,
	// same limitation Modbus reads have.
	if rosctr == 0x01 && (fc == 0x04 || fc == 0x05) {

		if item, ok := parseS7FirstItemAddress(param); ok {

			msg.Details["s7_area"] = item.area
			msg.Details["address"] = item.bitAddress

			if item.area == "DB" {
				msg.Details["s7_db"] = item.dbNumber
			}

			// WriteVar's request carries the value being written in
			// its own DATA section (right after the parameter
			// block) — ReadVar's request is just the query, no value
			// yet.
			if fc == 0x05 && dataLength > 0 && len(s7) >= headerLen+int(paramLength)+int(dataLength) {

				dataSection := s7[headerLen+int(paramLength) : headerLen+int(paramLength)+int(dataLength)]

				if value, ok := parseS7FirstItemValue(dataSection); ok {
					msg.Details["value"] = value
				}
			}
		}
	}

	return msg, true
}
