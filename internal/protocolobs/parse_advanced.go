package protocolobs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func parseKerberosUDP(p core.Packet, d []byte) (Observation, bool) {
	o := baseUDP(p, "kerberos")
	return parseKerberosObservation(o, d)
}

func parseKerberosTCP(c core.TCPStreamChunk, d []byte) (Observation, bool) {
	o := baseTCP(c, "kerberos")
	// Kerberos over TCP has a four-byte record length prefix.
	if len(d) >= 5 {
		n := int(binary.BigEndian.Uint32(d[:4]))
		if n > 0 && n <= len(d)-4 {
			d = d[4 : 4+n]
			o.Attributes["record_length"] = strconv.Itoa(n)
		}
	}
	return parseKerberosObservation(o, d)
}

func parseKerberosObservation(o Observation, d []byte) (Observation, bool) {
	if len(d) < 2 {
		return Observation{}, false
	}
	// Kerberos messages use ASN.1 APPLICATION tags 10-30 (0x6a-0x7e).
	tag := int(d[0] & 0x1f)
	if d[0]&0x60 != 0x60 || tag < 10 || tag > 30 {
		return Observation{}, false
	}
	names := map[int]string{10: "as_req", 11: "as_rep", 12: "tgs_req", 13: "tgs_rep", 14: "ap_req", 15: "ap_rep", 20: "krb_safe", 21: "krb_priv", 22: "krb_cred", 30: "krb_error"}
	op := names[tag]
	if op == "" {
		op = "message_" + strconv.Itoa(tag)
	}
	o.Operation = op
	o.Summary = "Kerberos " + strings.ReplaceAll(op, "_", " ")
	o.Attributes["message_type"] = strconv.Itoa(tag)
	if realm := kerberosRealmHeuristic(d); realm != "" {
		o.Attributes["realm"] = realm
		o.Host = realm
	}
	return o, true
}

func kerberosRealmHeuristic(d []byte) string {
	// Realm strings are encoded as ASN.1 GeneralString ([APPLICATION payload]
	// usually tag 0x1b). Extract only conservative DNS-like uppercase values.
	for i := 0; i+2 < len(d); i++ {
		if d[i] != 0x1b {
			continue
		}
		l := int(d[i+1])
		if l <= 0 || l > 255 || i+2+l > len(d) {
			continue
		}
		s := string(d[i+2 : i+2+l])
		if isRealm(s) {
			return s
		}
	}
	return ""
}

func isRealm(s string) bool {
	if len(s) < 3 || len(s) > 255 || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(unicode.IsUpper(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func parseDCERPC(c core.TCPStreamChunk, d []byte) (Observation, bool) {
	if len(d) < 16 || d[0] != 5 || d[1] != 0 {
		return Observation{}, false
	}
	packetType := d[2]
	names := map[byte]string{0: "request", 2: "response", 3: "fault", 11: "bind", 12: "bind_ack", 13: "bind_nak", 14: "alter_context", 15: "alter_context_resp", 16: "auth3", 17: "shutdown", 18: "cancel", 19: "orphaned"}
	op := names[packetType]
	if op == "" {
		op = "pdu_" + strconv.Itoa(int(packetType))
	}
	o := baseTCP(c, "dce_rpc")
	o.Operation = op
	o.Summary = "DCE/RPC " + strings.ReplaceAll(op, "_", " ")
	o.Attributes["packet_type"] = strconv.Itoa(int(packetType))
	o.Attributes["flags"] = fmt.Sprintf("0x%02x", d[3])
	little := d[4]&0x10 != 0
	if len(d) >= 16 {
		if little {
			o.Attributes["fragment_length"] = strconv.Itoa(int(binary.LittleEndian.Uint16(d[8:10])))
			o.Attributes["call_id"] = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(d[12:16])), 10)
		} else {
			o.Attributes["fragment_length"] = strconv.Itoa(int(binary.BigEndian.Uint16(d[8:10])))
			o.Attributes["call_id"] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(d[12:16])), 10)
		}
	}
	if packetType == 11 && len(d) >= 40 {
		// First abstract syntax UUID in a bind PDU. UUID byte ordering follows DCE.
		off := 32
		if off+16 <= len(d) {
			o.Attributes["interface_uuid"] = formatDCEUUID(d[off : off+16])
		}
	}
	return o, true
}

func formatDCEUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%s",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8], b[9], hex.EncodeToString(b[10:16]))
}

func parseONCRPC(base Observation, d []byte) (Observation, bool) {
	if len(d) < 24 {
		return Observation{}, false
	}
	// Strip RFC 5531 record marker for RPC over TCP.
	if base.Transport == "tcp" && len(d) >= 4 {
		marker := binary.BigEndian.Uint32(d[:4])
		n := int(marker & 0x7fffffff)
		if n >= 24 && n <= len(d)-4 {
			d = d[4 : 4+n]
			base.Attributes["last_fragment"] = strconv.FormatBool(marker&0x80000000 != 0)
		}
	}
	if len(d) < 24 {
		return Observation{}, false
	}
	msgType := binary.BigEndian.Uint32(d[4:8])
	base.Protocol = "nfs"
	base.Attributes["xid"] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(d[0:4])), 10)
	if msgType == 0 {
		rpcVersion := binary.BigEndian.Uint32(d[8:12])
		program := binary.BigEndian.Uint32(d[12:16])
		version := binary.BigEndian.Uint32(d[16:20])
		procedure := binary.BigEndian.Uint32(d[20:24])
		if rpcVersion != 2 || program != 100003 {
			return Observation{}, false
		}
		base.Operation = nfsProcedure(version, procedure)
		base.Summary = "NFS " + strings.ReplaceAll(base.Operation, "_", " ")
		base.Attributes["rpc_message"] = "call"
		base.Attributes["nfs_version"] = strconv.FormatUint(uint64(version), 10)
		base.Attributes["procedure"] = strconv.FormatUint(uint64(procedure), 10)
		return base, true
	}
	if msgType == 1 {
		base.Operation = "reply"
		base.Summary = "NFS RPC reply"
		base.Attributes["rpc_message"] = "reply"
		if len(d) >= 12 {
			base.Status = strconv.FormatUint(uint64(binary.BigEndian.Uint32(d[8:12])), 10)
		}
		return base, true
	}
	return Observation{}, false
}

func nfsProcedure(version, proc uint32) string {
	if proc == 0 {
		return "null"
	}
	if version == 3 {
		names := map[uint32]string{1: "getattr", 2: "setattr", 3: "lookup", 4: "access", 5: "readlink", 6: "read", 7: "write", 8: "create", 9: "mkdir", 10: "symlink", 11: "mknod", 12: "remove", 13: "rmdir", 14: "rename", 15: "link", 16: "readdir", 17: "readdirplus", 18: "fsstat", 19: "fsinfo", 20: "pathconf", 21: "commit"}
		if n := names[proc]; n != "" {
			return n
		}
	}
	if version == 2 {
		names := map[uint32]string{1: "getattr", 2: "setattr", 4: "lookup", 5: "readlink", 6: "read", 8: "write", 9: "create", 10: "remove", 11: "rename", 12: "link", 13: "symlink", 14: "mkdir", 15: "rmdir", 16: "readdir", 17: "statfs"}
		if n := names[proc]; n != "" {
			return n
		}
	}
	if version == 4 && proc == 1 {
		return "compound"
	}
	return "procedure_" + strconv.FormatUint(uint64(proc), 10)
}

func parseMSSQL(c core.TCPStreamChunk, d []byte) (Observation, bool) {
	if len(d) < 8 {
		return Observation{}, false
	}
	typ := d[0]
	names := map[byte]string{1: "sql_batch", 2: "pre_tds7_login", 3: "rpc", 4: "tabular_response", 6: "attention", 7: "bulk_load", 14: "transaction_manager", 16: "login7", 17: "sspi", 18: "prelogin"}
	op := names[typ]
	if op == "" {
		return Observation{}, false
	}
	length := int(binary.BigEndian.Uint16(d[2:4]))
	if length < 8 {
		return Observation{}, false
	}
	o := baseTCP(c, "mssql")
	o.Operation = op
	o.Summary = "MSSQL " + strings.ReplaceAll(op, "_", " ")
	o.Attributes["packet_type"] = fmt.Sprintf("0x%02x", typ)
	o.Attributes["status_flags"] = fmt.Sprintf("0x%02x", d[1])
	o.Attributes["packet_length"] = strconv.Itoa(length)
	o.Attributes["packet_id"] = strconv.Itoa(int(d[6]))
	o.Encrypted = typ == 17
	if typ == 18 && len(d) > 8 {
		o.Attributes["prelogin"] = "true"
	}
	return o, true
}

func parseDTLS(p core.Packet, d []byte) (Observation, bool) {
	if len(d) < 13 || !(d[1] == 0xfe && (d[2] == 0xff || d[2] == 0xfd || d[2] == 0xfc)) {
		return Observation{}, false
	}
	content := map[byte]string{20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data", 24: "heartbeat"}[d[0]]
	if content == "" {
		return Observation{}, false
	}
	o := baseUDP(p, "dtls")
	o.Encrypted = true
	o.Operation = content
	o.Summary = "DTLS " + strings.ReplaceAll(content, "_", " ")
	o.Attributes["version"] = fmt.Sprintf("0x%02x%02x", d[1], d[2])
	o.Attributes["epoch"] = strconv.Itoa(int(binary.BigEndian.Uint16(d[3:5])))
	o.Attributes["sequence"] = strconv.FormatUint(readUint48(d[5:11]), 10)
	if d[0] == 22 && len(d) >= 14 {
		hs := map[byte]string{1: "client_hello", 2: "server_hello", 3: "hello_verify_request", 11: "certificate", 12: "server_key_exchange", 13: "certificate_request", 14: "server_hello_done", 15: "certificate_verify", 16: "client_key_exchange", 20: "finished"}[d[13]]
		if hs != "" {
			o.Operation = hs
			o.Summary = "DTLS " + strings.ReplaceAll(hs, "_", " ")
		}
	}
	return o, true
}

func readUint48(b []byte) uint64 {
	if len(b) < 6 {
		return 0
	}
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

func parseOpenVPN(base Observation, d []byte) (Observation, bool) {
	if len(d) < 2 {
		return Observation{}, false
	}
	opcode := d[0] >> 3
	names := map[byte]string{1: "control_hard_reset_client_v1", 2: "control_hard_reset_server_v1", 3: "control_soft_reset_v1", 4: "control_v1", 5: "ack_v1", 6: "data_v1", 7: "control_hard_reset_client_v2", 8: "control_hard_reset_server_v2", 9: "data_v2", 10: "control_hard_reset_client_v3"}
	op := names[opcode]
	if op == "" {
		return Observation{}, false
	}
	base.Protocol = "openvpn"
	base.Encrypted = true
	base.Operation = op
	base.Summary = "OpenVPN " + strings.ReplaceAll(op, "_", " ")
	base.Attributes["opcode"] = strconv.Itoa(int(opcode))
	base.Attributes["key_id"] = strconv.Itoa(int(d[0] & 0x07))
	return base, true
}

func parseBitTorrentTCP(c core.TCPStreamChunk, d []byte) (Observation, bool) {
	sig := []byte("\x13BitTorrent protocol")
	idx := bytes.Index(d, sig)
	if idx < 0 {
		return Observation{}, false
	}
	o := baseTCP(c, "bittorrent")
	o.Operation = "handshake"
	o.Summary = "BitTorrent handshake"
	if len(d) >= idx+68 {
		o.Attributes["info_hash"] = hex.EncodeToString(d[idx+28 : idx+48])
		peer := d[idx+48 : idx+68]
		if isPrintableASCII(peer) {
			o.Attributes["peer_id"] = trim(string(peer), 80)
		}
	}
	return o, true
}

func parseBitTorrentUDP(p core.Packet, d []byte) (Observation, bool) {
	if len(d) < 16 {
		return Observation{}, false
	}
	actionOff := 8
	// Initial tracker connect uses the magic connection ID.
	if binary.BigEndian.Uint64(d[:8]) != 0x41727101980 && len(d) < 20 {
		return Observation{}, false
	}
	action := binary.BigEndian.Uint32(d[actionOff : actionOff+4])
	names := map[uint32]string{0: "connect", 1: "announce", 2: "scrape", 3: "error"}
	op := names[action]
	if op == "" {
		return Observation{}, false
	}
	o := baseUDP(p, "bittorrent")
	o.Operation = "tracker_" + op
	o.Summary = "BitTorrent tracker " + op
	o.Attributes["transaction_id"] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(d[12:16])), 10)
	if action == 1 && len(d) >= 36 {
		o.Attributes["info_hash"] = hex.EncodeToString(d[16:36])
	}
	return o, true
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
