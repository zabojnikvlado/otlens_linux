// Package streamproto classifies application protocols from reassembled stream
// bytes. Classification is deliberately conservative: a protocol is only
// returned with high confidence when its framing invariants are present.
package streamproto

import "bytes"

// Result describes a stream classification decision.
type Result struct {
	Protocol   string `json:"protocol"`
	Confidence uint8  `json:"confidence"` // 0..100
	Reason     string `json:"reason,omitempty"`
}

// DetectResult classifies a byte slice and explains the decision.
func DetectResult(data []byte) Result {
	if len(data) >= 8 && data[0] == 0 && (bytes.Equal(data[4:8], []byte{0xfe, 'S', 'M', 'B'}) || bytes.Equal(data[4:8], []byte{0xfd, 'S', 'M', 'B'})) {
		return Result{"smb", 100, "netbios session header followed by SMB signature"}
	}
	if len(data) >= 4 && (bytes.Equal(data[:4], []byte{0xfe, 'S', 'M', 'B'}) || bytes.Equal(data[:4], []byte{0xfd, 'S', 'M', 'B'})) {
		return Result{"smb", 98, "SMB2/3 signature"}
	}
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04 {
		length := int(data[3])<<8 | int(data[4])
		if length > 0 && length <= (1<<14)+2048 {
			return Result{"tls", 95, "valid TLS handshake record header"}
		}
	}
	if len(data) >= 8 && (bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST ")) || bytes.HasPrefix(data, []byte("HTTP/")) || bytes.HasPrefix(data, []byte("PUT ")) || bytes.HasPrefix(data, []byte("HEAD ")) || bytes.HasPrefix(data, []byte("DELETE ")) || bytes.HasPrefix(data, []byte("OPTIONS "))) {
		return Result{"http", 95, "HTTP request/status line"}
	}
	// Modbus/TCP MBAP: protocol id 0, length includes unit id + PDU and
	// must fit the available bytes when the complete ADU is present.
	if len(data) >= 8 && data[2] == 0 && data[3] == 0 {
		length := int(data[4])<<8 | int(data[5])
		if length >= 2 && length <= 254 {
			confidence := uint8(88)
			if length+6 <= len(data) {
				confidence = 96
			}
			return Result{"modbus_tcp", confidence, "valid MBAP protocol id and length"}
		}
	}
	if len(data) >= 16 && data[0] == 5 && data[1] == 0 && data[4] == 0x10 {
		return Result{"dcerpc", 92, "DCE/RPC v5 connection-oriented header"}
	}
	if len(data) >= 2 && data[0] == 0x05 && data[1] == 0x64 {
		return Result{"dnp3", 85, "DNP3 link-layer start bytes"}
	}
	if len(data) >= 2 && data[0] == 0x68 && int(data[1])+2 <= len(data) {
		return Result{"iec104", 90, "valid IEC-104 APDU length"}
	}
	return Result{"unknown", 0, "no supported framing signature"}
}

// Detect preserves the original API used by existing callers.
func Detect(data []byte) string { return DetectResult(data).Protocol }
