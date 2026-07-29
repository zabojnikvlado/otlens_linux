package protocolobs

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

func baseUDP(p core.Packet, proto string) Observation {
	return Observation{Timestamp: p.Timestamp, Protocol: proto, Transport: "udp", SrcIP: p.SrcIP, DstIP: p.DstIP, SrcPort: p.SrcPort, DstPort: p.DstPort, FromAnalysis: p.FromAnalysis, Attributes: map[string]string{}}
}
func baseTCP(c core.TCPStreamChunk, proto string) Observation {
	return Observation{Timestamp: c.Timestamp, Protocol: proto, Transport: "tcp", SrcIP: c.SrcIP, DstIP: c.DstIP, SrcPort: c.SrcPort, DstPort: c.DstPort, Attributes: map[string]string{}}
}

func parseUDP(p core.Packet) []Observation {
	return parseUDPWithContext(p, nil)
}

func parseUDPWithContext(p core.Packet, context *udpconversation.ParseContext) []Observation {
	observations := parseUDPPacket(p)
	if context != nil {
		for index := range observations {
			observations[index].ConversationID = context.ConversationID
			observations[index].Direction = string(context.Direction)
			observations[index].RTTMillis = context.RTTMillis
		}
	}
	return observations
}

func parseUDPPacket(p core.Packet) []Observation {
	d := p.AppPayload
	switch {
	case p.SrcPort == 88 || p.DstPort == 88:
		if o, ok := parseKerberosUDP(p, d); ok {
			return []Observation{o}
		}
	case p.SrcPort == 2049 || p.DstPort == 2049:
		if o, ok := parseONCRPC(baseUDP(p, "nfs"), d); ok {
			return []Observation{o}
		}
	case p.SrcPort == 1194 || p.DstPort == 1194:
		if o, ok := parseOpenVPN(baseUDP(p, "openvpn"), d); ok {
			return []Observation{o}
		}
	case p.SrcPort == 443 || p.DstPort == 443 || p.SrcPort == 5684 || p.DstPort == 5684:
		if o, ok := parseDTLS(p, d); ok {
			return []Observation{o}
		}
	case p.SrcPort == 6969 || p.DstPort == 6969:
		if o, ok := parseBitTorrentUDP(p, d); ok {
			return []Observation{o}
		}
	case p.SrcPort == 67 || p.SrcPort == 68 || p.DstPort == 67 || p.DstPort == 68:
		if o, ok := parseDHCP(p, d); ok {
			return []Observation{o}
		}
	case p.SrcPort == 123 || p.DstPort == 123:
		if len(d) >= 48 {
			o := baseUDP(p, "ntp")
			o.Operation = map[bool]string{true: "response", false: "request"}[p.SrcPort == 123]
			o.Attributes["version"] = strconv.Itoa(int((d[0] >> 3) & 7))
			o.Attributes["mode"] = strconv.Itoa(int(d[0] & 7))
			o.Attributes["stratum"] = strconv.Itoa(int(d[1]))
			o.Summary = "NTP " + o.Operation
			return []Observation{o}
		}
	case p.SrcPort == 161 || p.SrcPort == 162 || p.DstPort == 161 || p.DstPort == 162:
		if o, ok := parseSNMP(p, d); ok {
			return []Observation{o}
		}
	case p.SrcPort == 5060 || p.DstPort == 5060:
		if o, ok := parseSIP(baseUDP(p, "sip"), d); ok {
			return []Observation{o}
		}
	}
	return nil
}

func parseTCP(c core.TCPStreamChunk) []Observation {
	d := c.Data
	if len(d) == 0 {
		return nil
	}
	// Signature-based protocols before generic plaintext detection.
	if o, ok := parseBitTorrentTCP(c, d); ok {
		return []Observation{o}
	}
	if o, ok := parseDCERPC(c, d); ok {
		return []Observation{o}
	}
	// TLS before port-based plaintext protocols.
	if len(d) >= 5 && (d[0] == 0x16 || d[0] == 0x14 || d[0] == 0x15 || d[0] == 0x17) && d[1] == 3 {
		if o, ok := parseTLS(c, d); ok {
			return []Observation{o}
		}
	}
	if o, ok := parseHTTP(c, d); ok {
		return []Observation{o}
	}
	ports := []uint16{c.SrcPort, c.DstPort}
	has := func(p uint16) bool { return ports[0] == p || ports[1] == p }
	switch {
	case has(88):
		if o, ok := parseKerberosTCP(c, d); ok {
			return []Observation{o}
		}
	case has(135):
		if o, ok := parseDCERPC(c, d); ok {
			return []Observation{o}
		}
	case has(2049):
		if o, ok := parseONCRPC(baseTCP(c, "nfs"), d); ok {
			return []Observation{o}
		}
	case has(1433):
		if o, ok := parseMSSQL(c, d); ok {
			return []Observation{o}
		}
	case has(1194):
		if o, ok := parseOpenVPN(baseTCP(c, "openvpn"), d); ok {
			return []Observation{o}
		}
	case has(21):
		return parseLineProtocol(baseTCP(c, "ftp"), d, "ftp")
	case has(25) || has(587):
		return parseLineProtocol(baseTCP(c, "smtp"), d, "smtp")
	case has(143):
		return parseLineProtocol(baseTCP(c, "imap"), d, "imap")
	case has(110):
		return parseLineProtocol(baseTCP(c, "pop3"), d, "pop3")
	case has(22):
		if o, ok := parseSSH(c, d); ok {
			return []Observation{o}
		}
	case has(5060):
		if o, ok := parseSIP(baseTCP(c, "sip"), d); ok {
			return []Observation{o}
		}
	case has(161) || has(162): // uncommon SNMP/TCP
		p := core.Packet{Timestamp: c.Timestamp, SrcIP: c.SrcIP, DstIP: c.DstIP, SrcPort: c.SrcPort, DstPort: c.DstPort, AppPayload: d}
		if o, ok := parseSNMP(p, d); ok {
			o.Transport = "tcp"
			return []Observation{o}
		}
	}
	return nil
}

func parseHTTP(c core.TCPStreamChunk, d []byte) (Observation, bool) {
	s := string(d)
	lineEnd := strings.Index(s, "\r\n")
	if lineEnd < 0 {
		return Observation{}, false
	}
	first := s[:lineEnd]
	fields := strings.Fields(first)
	if len(fields) < 2 {
		return Observation{}, false
	}
	o := baseTCP(c, "http")
	if strings.HasPrefix(first, "HTTP/") {
		o.Operation = "response"
		o.Status = fields[1]
		o.Summary = first
	} else {
		methods := " GET POST PUT DELETE PATCH HEAD OPTIONS CONNECT TRACE "
		if !strings.Contains(methods, " "+strings.ToUpper(fields[0])+" ") {
			return Observation{}, false
		}
		o.Operation = strings.ToUpper(fields[0])
		o.Resource = fields[1]
		o.Summary = o.Operation + " " + o.Resource
	}
	for _, line := range strings.Split(s[lineEnd+2:], "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "host":
			o.Host = strings.TrimSpace(v)
		case "user-agent":
			o.Attributes["user_agent"] = trim(strings.TrimSpace(v), 256)
		case "content-type":
			o.Attributes["content_type"] = trim(strings.TrimSpace(v), 128)
		}
	}
	return o, true
}

func parseTLS(c core.TCPStreamChunk, d []byte) (Observation, bool) {
	if len(d) < 5 {
		return Observation{}, false
	}
	o := baseTCP(c, "tls")
	o.Encrypted = true
	o.Operation = "record"
	o.Attributes["record_type"] = strconv.Itoa(int(d[0]))
	o.Attributes["record_version"] = fmt.Sprintf("%d.%d", d[1], d[2])
	o.Summary = "TLS record"
	if d[0] == 0x16 && len(d) >= 9 {
		typ := d[5]
		names := map[byte]string{1: "client_hello", 2: "server_hello", 11: "certificate"}
		if n := names[typ]; n != "" {
			o.Operation = n
			o.Summary = "TLS " + strings.ReplaceAll(n, "_", " ")
		}
		if typ == 1 {
			if sni, alpn := tlsClientHelloMetadata(d[5:]); sni != "" || alpn != "" {
				o.Host = sni
				o.Attributes["alpn"] = alpn
			}
		}
	}
	return o, true
}

func tlsClientHelloMetadata(h []byte) (string, string) {
	if len(h) < 42 || h[0] != 1 {
		return "", ""
	}
	body := h[4:]
	if len(body) < 34 {
		return "", ""
	}
	i := 34
	if i >= len(body) {
		return "", ""
	}
	sid := int(body[i])
	i += 1 + sid
	if i+2 > len(body) {
		return "", ""
	}
	cs := int(binary.BigEndian.Uint16(body[i : i+2]))
	i += 2 + cs
	if i >= len(body) {
		return "", ""
	}
	comp := int(body[i])
	i += 1 + comp
	if i+2 > len(body) {
		return "", ""
	}
	extLen := int(binary.BigEndian.Uint16(body[i : i+2]))
	i += 2
	end := i + extLen
	if end > len(body) {
		end = len(body)
	}
	var sni, alpn string
	for i+4 <= end {
		t := binary.BigEndian.Uint16(body[i : i+2])
		l := int(binary.BigEndian.Uint16(body[i+2 : i+4]))
		i += 4
		if i+l > end {
			break
		}
		v := body[i : i+l]
		i += l
		switch t {
		case 0:
			if len(v) >= 5 {
				n := int(binary.BigEndian.Uint16(v[3:5]))
				if 5+n <= len(v) {
					sni = string(v[5 : 5+n])
				}
			}
		case 16:
			if len(v) >= 3 {
				n := int(v[2])
				if 3+n <= len(v) {
					alpn = string(v[3 : 3+n])
				}
			}
		}
	}
	return sni, alpn
}

func parseLineProtocol(base Observation, d []byte, proto string) []Observation {
	if !utf8.Valid(d) {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(string(d), "\r\n", "\n"), "\n")
	out := make([]Observation, 0, 2)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])
		allowed := map[string]string{}
		switch proto {
		case "ftp":
			allowed = map[string]string{"USER": "user", "PASS": "authentication", "RETR": "download", "STOR": "upload", "DELE": "delete", "CWD": "change_directory", "LIST": "list", "PASV": "passive", "PORT": "active", "220": "response", "230": "response", "530": "response"}
		case "smtp":
			allowed = map[string]string{"HELO": "hello", "EHLO": "hello", "MAIL": "mail_from", "RCPT": "recipient", "DATA": "data", "AUTH": "authentication", "STARTTLS": "starttls", "220": "response", "250": "response", "550": "response"}
		case "imap":
			allowed = map[string]string{"LOGIN": "authentication", "AUTHENTICATE": "authentication", "SELECT": "select", "EXAMINE": "examine", "FETCH": "fetch", "STORE": "store", "SEARCH": "search", "LOGOUT": "logout"}
		case "pop3":
			allowed = map[string]string{"USER": "user", "PASS": "authentication", "STAT": "status", "LIST": "list", "RETR": "retrieve", "DELE": "delete", "QUIT": "quit", "+OK": "response", "-ERR": "error"}
		}
		op := allowed[cmd]
		if op == "" && proto == "imap" && len(parts) > 1 {
			cmd = strings.ToUpper(parts[1])
			op = allowed[cmd]
		}
		if op == "" {
			continue
		}
		o := base
		o.Operation = op
		o.Summary = proto + " " + op
		if (cmd == "USER" || cmd == "LOGIN") && len(parts) > 1 {
			o.Username = trim(parts[len(parts)-1], 128)
		}
		if (cmd == "RETR" || cmd == "STOR" || cmd == "DELE" || cmd == "CWD") && len(parts) > 1 {
			o.Resource = trim(parts[1], 256)
		}
		if cmd == "PASS" || cmd == "AUTH" || cmd == "AUTHENTICATE" {
			o.Attributes["credential_present"] = "true"
		}
		out = append(out, o)
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func parseSSH(c core.TCPStreamChunk, d []byte) (Observation, bool) {
	s := string(d)
	i := strings.Index(s, "SSH-")
	if i < 0 {
		return Observation{}, false
	}
	e := strings.IndexAny(s[i:], "\r\n")
	if e < 0 {
		e = len(s) - i
	}
	banner := trim(s[i:i+e], 255)
	o := baseTCP(c, "ssh")
	o.Encrypted = true
	o.Operation = "banner"
	o.Summary = banner
	o.Attributes["banner"] = banner
	return o, true
}
func parseSIP(o Observation, d []byte) (Observation, bool) {
	if !utf8.Valid(d) {
		return Observation{}, false
	}
	s := string(d)
	lineEnd := strings.IndexAny(s, "\r\n")
	if lineEnd < 0 {
		return Observation{}, false
	}
	first := strings.TrimSpace(s[:lineEnd])
	f := strings.Fields(first)
	if len(f) < 2 {
		return Observation{}, false
	}
	if strings.HasPrefix(first, "SIP/2.0") {
		o.Operation = "response"
		o.Status = f[1]
	} else {
		methods := " INVITE ACK BYE CANCEL REGISTER OPTIONS MESSAGE SUBSCRIBE NOTIFY "
		m := strings.ToUpper(f[0])
		if !strings.Contains(methods, " "+m+" ") {
			return Observation{}, false
		}
		o.Operation = m
		o.Resource = f[1]
	}
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "call-id":
			o.Attributes["call_id"] = trim(strings.TrimSpace(v), 128)
		case "cseq":
			parts := strings.Fields(v)
			if len(parts) >= 2 {
				o.Attributes["cseq"] = parts[0]
				o.Attributes["cseq_method"] = strings.ToUpper(parts[1])
			}
		case "from":
			o.Attributes["from"] = trim(strings.TrimSpace(v), 256)
			o.Attributes["from_tag"] = sipTag(v)
		case "to":
			o.Attributes["to"] = trim(strings.TrimSpace(v), 256)
			o.Attributes["to_tag"] = sipTag(v)
		case "user-agent":
			o.Attributes["user_agent"] = trim(strings.TrimSpace(v), 128)
		}
	}
	o.Summary = "SIP " + o.Operation
	return o, true
}

func sipTag(value string) string {
	for _, parameter := range strings.Split(value, ";")[1:] {
		key, tag, found := strings.Cut(strings.TrimSpace(parameter), "=")
		if found && strings.EqualFold(key, "tag") {
			return trim(strings.TrimSpace(tag), 128)
		}
	}
	return ""
}

func parseDHCP(p core.Packet, d []byte) (Observation, bool) {
	if len(d) < 240 || binary.BigEndian.Uint32(d[236:240]) != 0x63825363 {
		return Observation{}, false
	}
	o := baseUDP(p, "dhcp")
	o.Operation = map[byte]string{1: "request", 2: "reply"}[d[0]]
	o.Attributes["transaction_id"] = fmt.Sprintf("%08x", binary.BigEndian.Uint32(d[4:8]))
	if ip := net.IP(d[16:20]).String(); ip != "0.0.0.0" {
		o.Attributes["your_ip"] = ip
	}
	i := 240
	for i < len(d) {
		code := d[i]
		i++
		if code == 255 {
			break
		}
		if code == 0 {
			continue
		}
		if i >= len(d) {
			break
		}
		l := int(d[i])
		i++
		if i+l > len(d) {
			break
		}
		v := d[i : i+l]
		i += l
		switch code {
		case 12:
			o.Host = trim(string(v), 255)
		case 53:
			if len(v) > 0 {
				o.Operation = map[byte]string{1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}[v[0]]
			}
		case 50:
			if len(v) == 4 {
				o.Attributes["requested_ip"] = net.IP(v).String()
			}
		case 54:
			if len(v) == 4 {
				o.Attributes["server_id"] = net.IP(v).String()
			}
		}
	}
	o.Summary = "DHCP " + o.Operation
	return o, true
}

func parseSNMP(p core.Packet, d []byte) (Observation, bool) {
	if len(d) < 8 || d[0] != 0x30 {
		return Observation{}, false
	}
	o := baseUDP(p, "snmp")
	o.Operation = "message"
	if p.SrcPort == 162 || p.DstPort == 162 {
		o.Operation = "trap"
	}
	o.Attributes["ber_length"] = strconv.Itoa(len(d)) // lightweight BER walk for version/community/PDU
	i := 1
	_, n := berLen(d[i:])
	if n == 0 {
		return Observation{}, false
	}
	i += n
	if i+3 <= len(d) && d[i] == 0x02 {
		l := int(d[i+1])
		if i+2+l <= len(d) && l > 0 {
			o.Attributes["version"] = strconv.Itoa(int(d[i+2]))
			i += 2 + l
		}
	}
	if i+2 <= len(d) && d[i] == 0x04 {
		l := int(d[i+1])
		if i+2+l <= len(d) {
			o.Attributes["community"] = trim(string(d[i+2:i+2+l]), 64)
			i += 2 + l
		}
	}
	if i < len(d) {
		pdu := d[i]
		names := map[byte]string{0xa0: "get", 0xa1: "get_next", 0xa2: "response", 0xa3: "set", 0xa4: "trap_v1", 0xa5: "get_bulk", 0xa6: "inform", 0xa7: "trap_v2", 0xa8: "report"}
		if names[pdu] != "" {
			o.Operation = names[pdu]
		}
	}
	o.Summary = "SNMP " + o.Operation
	return o, true
}
func berLen(d []byte) (int, int) {
	if len(d) == 0 {
		return 0, 0
	}
	if d[0]&0x80 == 0 {
		return int(d[0]), 1
	}
	n := int(d[0] & 0x7f)
	if n == 0 || n > 4 || 1+n > len(d) {
		return 0, 0
	}
	v := 0
	for _, b := range d[1 : 1+n] {
		v = v<<8 | int(b)
	}
	return v, 1 + n
}
func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
