// Package streamproto classifies application protocols from stream bytes rather
// than relying exclusively on TCP port numbers.
package streamproto

import "bytes"

func Detect(data []byte) string {
	if len(data) >= 8 && data[0] == 0 && (bytes.Equal(data[4:8], []byte{0xfe, 'S', 'M', 'B'}) || bytes.Equal(data[4:8], []byte{0xfd, 'S', 'M', 'B'})) {
		return "smb"
	}
	if len(data) >= 4 && (bytes.Equal(data[:4], []byte{0xfe, 'S', 'M', 'B'}) || bytes.Equal(data[:4], []byte{0xfd, 'S', 'M', 'B'})) {
		return "smb"
	}
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04 {
		return "tls"
	}
	if len(data) >= 8 && (bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST ")) || bytes.HasPrefix(data, []byte("HTTP/")) || bytes.HasPrefix(data, []byte("PUT ")) || bytes.HasPrefix(data, []byte("HEAD "))) {
		return "http"
	}
	if len(data) >= 8 && data[2] == 0 && data[3] == 0 && data[6] == 0 && data[7] != 0 {
		return "modbus_tcp"
	}
	if len(data) >= 16 && data[0] == 5 && data[1] == 0 && data[4] == 0x10 {
		return "dcerpc"
	}
	return "unknown"
}
