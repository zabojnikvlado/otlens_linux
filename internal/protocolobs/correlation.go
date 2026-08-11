package protocolobs

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

const (
	exchangeTimeout     = 5 * time.Second
	maxPendingExchanges = 5000
	sipTimeout          = 5 * time.Minute
)

type DHCPExchange struct {
	ConversationID string
	TransactionID  uint32
	ClientMAC      string
	StartedAt      time.Time
	CompletedAt    time.Time
	AssignedIP     string
	LeaseTime      time.Duration
	Gateway        string
	DNSServers     []string
	Hostname       string
	VendorClass    string
	Sequence       []string
	Incomplete     bool
	Invalid        bool
	TimedOut       bool
}

type NTPExchange struct {
	ConversationID string
	RequestedAt    time.Time
	RespondedAt    time.Time
	RTT            time.Duration
	ServerStratum  uint8
	LeapIndicator  uint8
	ClockOffset    time.Duration
	OffsetValid    bool
	KoD            string
	TimedOut       bool
}

type SNMPExchange struct {
	ConversationID string
	RequestID      int64
	Version        int
	Operation      string
	RequestedAt    time.Time
	RespondedAt    time.Time
	ResponseTime   time.Duration
	ErrorStatus    int64
	Varbinds       int
	TimedOut       bool
}

type SIPDialog struct {
	ConversationID string
	CallID         string
	CSeq           string
	FromTag        string
	ToTag          string
	StartedAt      time.Time
	AnsweredAt     time.Time
	EndedAt        time.Time
	TimeToResponse time.Duration
	RingingTime    time.Duration
	Duration       time.Duration
	Status         string
	Sequence       []string
	Failed         bool
	Abandoned      bool
	TimedOut       bool
}

type DTLSHandshake struct {
	ConversationID  string
	StartedAt       time.Time
	CompletedAt     time.Time
	Status          string
	Version         string
	Epoch           uint16
	Retransmissions uint64
	Sequence        []string
	TimedOut        bool
}

type OpenVPNSession struct {
	ConversationID string
	KeyID          uint8
	StartedAt      time.Time
	LastSeenAt     time.Time
	ControlPackets uint64
	Resets         uint64
	Handshakes     uint64
	Keepalives     uint64
	LastOpcode     string
	TimedOut       bool
}

type BitTorrentExchange struct {
	ConversationID string
	TransactionID  uint32
	Operation      string
	RequestedAt    time.Time
	RespondedAt    time.Time
	RTT            time.Duration
	Error          bool
	TimedOut       bool
}

type dhcpKey struct {
	conversation, mac string
	xid               uint32
}
type ntpKey struct {
	conversation string
	transmit     uint64
	direction    udpconversation.Direction
}
type snmpKey struct {
	conversation string
	requestID    int64
	version      int
	direction    udpconversation.Direction
}
type sipKey struct{ conversation, callID string }
type btKey struct {
	conversation  string
	transactionID uint32
	direction     udpconversation.Direction
}
type dtlsPending struct {
	exchange DTLSHandshake
	seen     map[string]struct{}
}

type dhcpPending struct {
	exchange DHCPExchange
	lastSeen time.Time
	stage    int
}
type ntpPending struct {
	exchange NTPExchange
	t1       time.Time
}

type Correlator struct {
	mu          sync.Mutex
	timeout     time.Duration
	dhcpTimeout time.Duration
	snmpTimeout time.Duration
	sipTimeout  time.Duration
	maxPending  int
	dhcp        map[dhcpKey]*dhcpPending
	ntp         map[ntpKey]*ntpPending
	snmp        map[snmpKey]*SNMPExchange
	sip         map[sipKey]*SIPDialog
	dtls        map[string]*dtlsPending
	openvpn     map[string]*OpenVPNSession
	bt          map[btKey]*BitTorrentExchange
}

type CorrelatorConfig struct {
	Timeout     time.Duration
	DHCPTimeout time.Duration
	SNMPTimeout time.Duration
	SIPTimeout  time.Duration
	MaxPending  int
}

func NewCorrelator(timeout time.Duration) *Correlator {
	return NewCorrelatorWithConfig(CorrelatorConfig{Timeout: timeout, DHCPTimeout: timeout, SNMPTimeout: timeout, SIPTimeout: timeout})
}

func NewCorrelatorWithConfig(config CorrelatorConfig) *Correlator {
	if config.Timeout <= 0 {
		config.Timeout = exchangeTimeout
	}
	if config.DHCPTimeout <= 0 {
		config.DHCPTimeout = 60 * time.Second
	}
	if config.SNMPTimeout <= 0 {
		config.SNMPTimeout = 10 * time.Second
	}
	if config.SIPTimeout <= 0 {
		config.SIPTimeout = sipTimeout
	}
	if config.MaxPending <= 0 {
		config.MaxPending = maxPendingExchanges
	}
	return &Correlator{timeout: config.Timeout, dhcpTimeout: config.DHCPTimeout, snmpTimeout: config.SNMPTimeout, sipTimeout: config.SIPTimeout, maxPending: config.MaxPending, dhcp: map[dhcpKey]*dhcpPending{}, ntp: map[ntpKey]*ntpPending{}, snmp: map[snmpKey]*SNMPExchange{}, sip: map[sipKey]*SIPDialog{}, dtls: map[string]*dtlsPending{}, openvpn: map[string]*OpenVPNSession{}, bt: map[btKey]*BitTorrentExchange{}}
}

func (c *Correlator) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dhcp = map[dhcpKey]*dhcpPending{}
	c.ntp = map[ntpKey]*ntpPending{}
	c.snmp = map[snmpKey]*SNMPExchange{}
	c.sip = map[sipKey]*SIPDialog{}
	c.dtls = map[string]*dtlsPending{}
	c.openvpn = map[string]*OpenVPNSession{}
	c.bt = map[btKey]*BitTorrentExchange{}
}

func (c *Correlator) Observe(packet core.Packet, context udpconversation.ParseContext) []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case packet.SrcPort == 5060 || packet.DstPort == 5060:
		if result := c.sipLocked(packet, context); result != nil {
			return []any{*result}
		}
	case packet.SrcPort == 443 || packet.DstPort == 443 || packet.SrcPort == 5684 || packet.DstPort == 5684:
		if result := c.dtlsLocked(packet, context); result != nil {
			return []any{*result}
		}
	case packet.SrcPort == 1194 || packet.DstPort == 1194:
		if result := c.openvpnLocked(packet, context); result != nil {
			return []any{*result}
		}
	case packet.SrcPort == 6969 || packet.DstPort == 6969:
		if result := c.bitTorrentLocked(packet, context); result != nil {
			return []any{*result}
		}
	case packet.SrcPort == 67 || packet.SrcPort == 68 || packet.DstPort == 67 || packet.DstPort == 68:
		if result := c.dhcpLocked(packet, context); result != nil {
			return []any{*result}
		}
	case packet.SrcPort == 123 || packet.DstPort == 123:
		if result := c.ntpLocked(packet, context); result != nil {
			return []any{*result}
		}
	case packet.SrcPort == 161 || packet.DstPort == 161:
		if result := c.snmpLocked(packet, context); result != nil {
			return []any{*result}
		}
	}
	return nil
}

func (c *Correlator) Expire(now time.Time) []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []any
	for key, pending := range c.dhcp {
		if now.Sub(pending.lastSeen) > c.dhcpTimeout {
			delete(c.dhcp, key)
			pending.exchange.Incomplete = true
			pending.exchange.TimedOut = true
			out = append(out, pending.exchange)
		}
	}
	for key, pending := range c.ntp {
		if now.Sub(pending.exchange.RequestedAt) > c.timeout {
			delete(c.ntp, key)
			pending.exchange.TimedOut = true
			out = append(out, pending.exchange)
		}
	}
	for key, pending := range c.snmp {
		if now.Sub(pending.RequestedAt) > c.snmpTimeout {
			delete(c.snmp, key)
			pending.TimedOut = true
			out = append(out, *pending)
		}
	}
	for key, pending := range c.sip {
		if now.Sub(pending.StartedAt) > c.sipTimeout {
			delete(c.sip, key)
			pending.Abandoned = true
			pending.TimedOut = true
			out = append(out, *pending)
		}
	}
	for key, pending := range c.dtls {
		if now.Sub(pending.exchange.StartedAt) > c.timeout {
			delete(c.dtls, key)
			pending.exchange.Status = "timeout"
			pending.exchange.TimedOut = true
			out = append(out, pending.exchange)
		}
	}
	for key, pending := range c.openvpn {
		if now.Sub(pending.LastSeenAt) > c.timeout {
			delete(c.openvpn, key)
			pending.TimedOut = true
			out = append(out, *pending)
		}
	}
	for key, pending := range c.bt {
		if now.Sub(pending.RequestedAt) > c.timeout {
			delete(c.bt, key)
			pending.TimedOut = true
			out = append(out, *pending)
		}
	}
	return out
}

type dhcpMessage struct {
	xid                                              uint32
	mac, kind, assignedIP, gateway, hostname, vendor string
	lease                                            time.Duration
	dns                                              []string
}

func decodeDHCP(data []byte) (dhcpMessage, bool) {
	if len(data) < 240 || binary.BigEndian.Uint32(data[236:240]) != 0x63825363 {
		return dhcpMessage{}, false
	}
	hlen := int(data[2])
	if hlen <= 0 || hlen > 16 || 28+hlen > len(data) {
		return dhcpMessage{}, false
	}
	m := dhcpMessage{xid: binary.BigEndian.Uint32(data[4:8]), mac: net.HardwareAddr(data[28 : 28+hlen]).String()}
	if ip := net.IP(data[16:20]).String(); ip != "0.0.0.0" {
		m.assignedIP = ip
	}
	for i := 240; i < len(data); {
		code := data[i]
		i++
		if code == 255 {
			break
		}
		if code == 0 {
			continue
		}
		if i >= len(data) {
			return dhcpMessage{}, false
		}
		size := int(data[i])
		i++
		if i+size > len(data) {
			return dhcpMessage{}, false
		}
		value := data[i : i+size]
		i += size
		switch code {
		case 3:
			if size >= 4 {
				m.gateway = net.IP(value[:4]).String()
			}
		case 6:
			for j := 0; j+4 <= size; j += 4 {
				m.dns = append(m.dns, net.IP(value[j:j+4]).String())
			}
		case 12:
			m.hostname = string(value)
		case 51:
			if size == 4 {
				m.lease = time.Duration(binary.BigEndian.Uint32(value)) * time.Second
			}
		case 53:
			if size == 1 {
				m.kind = map[byte]string{1: "discover", 2: "offer", 3: "request", 5: "ack", 6: "nak"}[value[0]]
			}
		case 60:
			m.vendor = string(value)
		}
	}
	return m, m.kind != ""
}

func (c *Correlator) dhcpLocked(packet core.Packet, context udpconversation.ParseContext) *DHCPExchange {
	m, ok := decodeDHCP(packet.AppPayload)
	if !ok {
		return nil
	}
	key := dhcpKey{context.ConversationID, m.mac, m.xid}
	pending := c.dhcp[key]
	expected := []string{"discover", "offer", "request", "ack"}
	if pending == nil {
		if len(c.dhcp) >= c.maxPending {
			evictOldestDHCP(c.dhcp)
		}
		pending = &dhcpPending{exchange: DHCPExchange{ConversationID: context.ConversationID, TransactionID: m.xid, ClientMAC: m.mac, StartedAt: packet.Timestamp}}
		c.dhcp[key] = pending
	}
	pending.lastSeen = packet.Timestamp
	if pending.stage >= len(expected) || m.kind != expected[pending.stage] {
		pending.exchange.Invalid = true
	}
	if pending.stage < len(expected) && m.kind == expected[pending.stage] {
		pending.stage++
	}
	pending.exchange.Sequence = append(pending.exchange.Sequence, m.kind)
	if m.assignedIP != "" {
		pending.exchange.AssignedIP = m.assignedIP
	}
	if m.lease != 0 {
		pending.exchange.LeaseTime = m.lease
	}
	if m.gateway != "" {
		pending.exchange.Gateway = m.gateway
	}
	if len(m.dns) > 0 {
		pending.exchange.DNSServers = append([]string(nil), m.dns...)
	}
	if m.hostname != "" {
		pending.exchange.Hostname = m.hostname
	}
	if m.vendor != "" {
		pending.exchange.VendorClass = m.vendor
	}
	if m.kind == "ack" || m.kind == "nak" {
		delete(c.dhcp, key)
		pending.exchange.CompletedAt = packet.Timestamp
		pending.exchange.Incomplete = pending.stage != 4 || m.kind == "nak"
		result := pending.exchange
		return &result
	}
	return nil
}

const ntpEpochOffset = 2208988800

func ntpTime(value uint64) (time.Time, bool) {
	seconds := uint32(value >> 32)
	fraction := uint32(value)
	if seconds == 0 {
		return time.Time{}, false
	}
	nanos := int64(float64(fraction) * 1e9 / 4294967296.0)
	return time.Unix(int64(seconds)-ntpEpochOffset, nanos), true
}
func (c *Correlator) ntpLocked(packet core.Packet, context udpconversation.ParseContext) *NTPExchange {
	d := packet.AppPayload
	if len(d) < 48 {
		return nil
	}
	mode := d[0] & 7
	transmit := binary.BigEndian.Uint64(d[40:48])
	if mode == 3 {
		if transmit == 0 {
			return nil
		}
		key := ntpKey{context.ConversationID, transmit, context.Direction}
		if _, exists := c.ntp[key]; !exists {
			if len(c.ntp) >= c.maxPending {
				evictOldestNTP(c.ntp)
			}
			t1, valid := ntpTime(transmit)
			if !valid {
				return nil
			}
			c.ntp[key] = &ntpPending{exchange: NTPExchange{ConversationID: context.ConversationID, RequestedAt: packet.Timestamp}, t1: t1}
		}
		return nil
	}
	if mode != 4 {
		return nil
	}
	originate := binary.BigEndian.Uint64(d[24:32])
	key := ntpKey{context.ConversationID, originate, oppositeDirection(context.Direction)}
	pending := c.ntp[key]
	if pending == nil {
		return nil
	}
	delete(c.ntp, key)
	x := pending.exchange
	x.RespondedAt = packet.Timestamp
	if !packet.Timestamp.Before(x.RequestedAt) {
		x.RTT = packet.Timestamp.Sub(x.RequestedAt)
	}
	x.LeapIndicator = d[0] >> 6
	x.ServerStratum = d[1]
	if x.ServerStratum == 0 {
		x.KoD = strings.TrimSpace(string(d[12:16]))
	}
	t2, ok2 := ntpTime(binary.BigEndian.Uint64(d[32:40]))
	t3, ok3 := ntpTime(transmit)
	if ok2 && ok3 {
		x.ClockOffset = (t2.Sub(pending.t1) + t3.Sub(packet.Timestamp)) / 2
		x.OffsetValid = true
	}
	return &x
}

type snmpMessage struct {
	version                int
	requestID, errorStatus int64
	operation              string
	varbinds               int
	response               bool
}

func readTLV(data []byte, offset int) (byte, []byte, int, bool) {
	if offset+2 > len(data) {
		return 0, nil, 0, false
	}
	tag := data[offset]
	offset++
	length, n := berLen(data[offset:])
	if n == 0 {
		return 0, nil, 0, false
	}
	offset += n
	if length < 0 || offset+length > len(data) {
		return 0, nil, 0, false
	}
	return tag, data[offset : offset+length], offset + length, true
}
func berInt(data []byte) int64 {
	var value int64
	for _, b := range data {
		value = value<<8 | int64(b)
	}
	return value
}
func decodeSNMP(data []byte) (snmpMessage, bool) {
	tag, body, _, ok := readTLV(data, 0)
	if !ok || tag != 0x30 {
		return snmpMessage{}, false
	}
	_, v, next, ok := readTLV(body, 0)
	if !ok {
		return snmpMessage{}, false
	}
	version := int(berInt(v))
	_, _, next, ok = readTLV(body, next)
	if !ok {
		return snmpMessage{}, false
	}
	pdu, pduBody, _, ok := readTLV(body, next)
	if !ok {
		return snmpMessage{}, false
	}
	names := map[byte]string{0xa0: "get", 0xa1: "get_next", 0xa2: "response", 0xa3: "set", 0xa5: "get_bulk"}
	op := names[pdu]
	if op == "" {
		return snmpMessage{}, false
	}
	_, id, pos, ok := readTLV(pduBody, 0)
	if !ok {
		return snmpMessage{}, false
	}
	_, errValue, pos, ok := readTLV(pduBody, pos)
	if !ok {
		return snmpMessage{}, false
	}
	_, _, pos, ok = readTLV(pduBody, pos)
	if !ok {
		return snmpMessage{}, false
	}
	tag, list, _, ok := readTLV(pduBody, pos)
	if !ok || tag != 0x30 {
		return snmpMessage{}, false
	}
	count := 0
	for pos = 0; pos < len(list); count++ {
		_, _, next, ok = readTLV(list, pos)
		if !ok {
			return snmpMessage{}, false
		}
		pos = next
	}
	return snmpMessage{version: version, requestID: berInt(id), errorStatus: berInt(errValue), operation: op, varbinds: count, response: pdu == 0xa2}, true
}
func (c *Correlator) snmpLocked(packet core.Packet, context udpconversation.ParseContext) *SNMPExchange {
	m, ok := decodeSNMP(packet.AppPayload)
	if !ok {
		return nil
	}
	if !m.response {
		key := snmpKey{context.ConversationID, m.requestID, m.version, context.Direction}
		if _, exists := c.snmp[key]; !exists {
			if len(c.snmp) >= c.maxPending {
				evictOldestSNMP(c.snmp)
			}
			c.snmp[key] = &SNMPExchange{ConversationID: context.ConversationID, RequestID: m.requestID, Version: m.version, Operation: m.operation, RequestedAt: packet.Timestamp, Varbinds: m.varbinds}
		}
		return nil
	}
	key := snmpKey{context.ConversationID, m.requestID, m.version, oppositeDirection(context.Direction)}
	x := c.snmp[key]
	if x == nil {
		return nil
	}
	delete(c.snmp, key)
	x.RespondedAt = packet.Timestamp
	if !packet.Timestamp.Before(x.RequestedAt) {
		x.ResponseTime = packet.Timestamp.Sub(x.RequestedAt)
	}
	x.ErrorStatus = m.errorStatus
	x.Varbinds = m.varbinds
	result := *x
	return &result
}

func (c *Correlator) sipLocked(packet core.Packet, context udpconversation.ParseContext) *SIPDialog {
	observation, ok := parseSIP(baseUDP(packet, "sip"), packet.AppPayload)
	if !ok {
		return nil
	}
	callID := observation.Attributes["call_id"]
	if callID == "" {
		return nil
	}
	key := sipKey{context.ConversationID, callID}
	dialog := c.sip[key]
	method := observation.Operation
	if method == "response" {
		method = observation.Status
	}
	if dialog == nil {
		dialog = &SIPDialog{ConversationID: context.ConversationID, CallID: callID, StartedAt: packet.Timestamp}
		c.sip[key] = dialog
		if observation.Operation != "INVITE" {
			dialog.Failed = true
		}
	}
	if dialog.CSeq == "" {
		dialog.CSeq = observation.Attributes["cseq"]
	}
	if dialog.FromTag == "" {
		dialog.FromTag = observation.Attributes["from_tag"]
	}
	if tag := observation.Attributes["to_tag"]; tag != "" {
		dialog.ToTag = tag
	}
	dialog.Sequence = append(dialog.Sequence, method)
	switch {
	case observation.Operation == "response":
		dialog.Status = observation.Status
		if dialog.TimeToResponse == 0 && !packet.Timestamp.Before(dialog.StartedAt) {
			dialog.TimeToResponse = packet.Timestamp.Sub(dialog.StartedAt)
		}
		if observation.Status == "180" && !packet.Timestamp.Before(dialog.StartedAt) {
			dialog.RingingTime = packet.Timestamp.Sub(dialog.StartedAt)
		}
		if observation.Status == "200" && strings.EqualFold(observation.Attributes["cseq_method"], "INVITE") {
			dialog.AnsweredAt = packet.Timestamp
		}
		if len(observation.Status) == 3 && observation.Status[0] >= '3' {
			dialog.Failed = true
			dialog.EndedAt = packet.Timestamp
			delete(c.sip, key)
			result := *dialog
			return &result
		}
	case observation.Operation == "BYE":
		dialog.EndedAt = packet.Timestamp
		if !dialog.AnsweredAt.IsZero() && !packet.Timestamp.Before(dialog.AnsweredAt) {
			dialog.Duration = packet.Timestamp.Sub(dialog.AnsweredAt)
		} else {
			dialog.Abandoned = true
		}
		delete(c.sip, key)
		result := *dialog
		return &result
	}
	return nil
}

func (c *Correlator) dtlsLocked(packet core.Packet, context udpconversation.ParseContext) *DTLSHandshake {
	observation, ok := parseDTLS(packet, packet.AppPayload)
	if !ok {
		return nil
	}
	if observation.Operation == "application_data" {
		return nil
	}
	pending := c.dtls[context.ConversationID]
	if pending == nil {
		pending = &dtlsPending{
			exchange: DTLSHandshake{
				ConversationID: context.ConversationID,
				StartedAt:      packet.Timestamp,
				Status:         "in_progress",
				Version:        observation.Attributes["version"],
			},
			seen: make(map[string]struct{}),
		}
		c.dtls[context.ConversationID] = pending
	}
	epoch, _ := strconv.ParseUint(observation.Attributes["epoch"], 10, 16)
	pending.exchange.Epoch = uint16(epoch)
	signature := observation.Operation + ":" + observation.Attributes["epoch"] + ":" + observation.Attributes["sequence"]
	if _, duplicate := pending.seen[signature]; duplicate {
		pending.exchange.Retransmissions++
		return nil
	}
	pending.seen[signature] = struct{}{}
	pending.exchange.Sequence = append(pending.exchange.Sequence, observation.Operation)
	if observation.Operation == "finished" {
		pending.exchange.CompletedAt = packet.Timestamp
		pending.exchange.Status = "complete"
		delete(c.dtls, context.ConversationID)
		result := pending.exchange
		return &result
	}
	return nil
}

func (c *Correlator) openvpnLocked(packet core.Packet, context udpconversation.ParseContext) *OpenVPNSession {
	observation, ok := parseOpenVPN(baseUDP(packet, "openvpn"), packet.AppPayload)
	if !ok {
		return nil
	}
	keyIDValue, _ := strconv.ParseUint(observation.Attributes["key_id"], 10, 8)
	key := context.ConversationID + ":" + observation.Attributes["key_id"]
	session := c.openvpn[key]
	if session == nil {
		session = &OpenVPNSession{ConversationID: context.ConversationID, KeyID: uint8(keyIDValue), StartedAt: packet.Timestamp}
		c.openvpn[key] = session
	}
	session.LastSeenAt = packet.Timestamp
	session.LastOpcode = observation.Operation
	switch {
	case strings.Contains(observation.Operation, "reset"):
		session.Resets++
		session.Handshakes++
		session.ControlPackets++
	case strings.HasPrefix(observation.Operation, "control"):
		session.ControlPackets++
	case observation.Operation == "ack_v1":
		session.Keepalives++
		session.ControlPackets++
	}
	// OpenVPN is long-lived; publish snapshots for meaningful state changes.
	result := *session
	return &result
}

func (c *Correlator) bitTorrentLocked(packet core.Packet, context udpconversation.ParseContext) *BitTorrentExchange {
	data := packet.AppPayload
	if len(data) < 8 {
		return nil
	}
	// Requests have connection-id/action/transaction-id. Responses have
	// action/transaction-id, so first try matching the compact response form.
	responseAction := binary.BigEndian.Uint32(data[0:4])
	responseTransaction := binary.BigEndian.Uint32(data[4:8])
	responseKey := btKey{context.ConversationID, responseTransaction, oppositeDirection(context.Direction)}
	if pending := c.bt[responseKey]; pending != nil && responseAction <= 3 {
		delete(c.bt, responseKey)
		pending.RespondedAt = packet.Timestamp
		if !packet.Timestamp.Before(pending.RequestedAt) {
			pending.RTT = packet.Timestamp.Sub(pending.RequestedAt)
		}
		pending.Error = responseAction == 3
		result := *pending
		return &result
	}
	if len(data) < 16 {
		return nil
	}
	action := binary.BigEndian.Uint32(data[8:12])
	if action > 2 {
		return nil
	}
	transaction := binary.BigEndian.Uint32(data[12:16])
	key := btKey{context.ConversationID, transaction, context.Direction}
	if _, duplicate := c.bt[key]; duplicate {
		return nil
	}
	operation := map[uint32]string{0: "connect", 1: "announce", 2: "scrape"}[action]
	c.bt[key] = &BitTorrentExchange{ConversationID: context.ConversationID, TransactionID: transaction, Operation: operation, RequestedAt: packet.Timestamp}
	return nil
}

func oppositeDirection(direction udpconversation.Direction) udpconversation.Direction {
	if direction == udpconversation.DirectionAToB {
		return udpconversation.DirectionBToA
	}
	return udpconversation.DirectionAToB
}

func exchangeEvent(value any) (core.EventType, time.Time) {
	switch x := value.(type) {
	case DHCPExchange:
		return core.EventDHCPExchange, firstTime(x.CompletedAt, x.StartedAt)
	case NTPExchange:
		return core.EventNTPExchange, firstTime(x.RespondedAt, x.RequestedAt)
	case SNMPExchange:
		return core.EventSNMPExchange, firstTime(x.RespondedAt, x.RequestedAt)
	case SIPDialog:
		return core.EventSIPDialog, firstTime(x.EndedAt, x.StartedAt)
	case DTLSHandshake:
		return core.EventDTLSHandshake, firstTime(x.CompletedAt, x.StartedAt)
	case OpenVPNSession:
		return core.EventOpenVPNSession, x.LastSeenAt
	case BitTorrentExchange:
		return core.EventBitTorrentExchange, firstTime(x.RespondedAt, x.RequestedAt)
	}
	return "", time.Time{}
}
func firstTime(preferred, fallback time.Time) time.Time {
	if !preferred.IsZero() {
		return preferred
	}
	return fallback
}

func evictOldestDHCP(pending map[dhcpKey]*dhcpPending) {
	var selected dhcpKey
	var oldest *dhcpPending
	for key, value := range pending {
		if oldest == nil || value.lastSeen.Before(oldest.lastSeen) {
			selected, oldest = key, value
		}
	}
	delete(pending, selected)
}

func evictOldestNTP(pending map[ntpKey]*ntpPending) {
	var selected ntpKey
	var oldest *ntpPending
	for key, value := range pending {
		if oldest == nil || value.exchange.RequestedAt.Before(oldest.exchange.RequestedAt) {
			selected, oldest = key, value
		}
	}
	delete(pending, selected)
}

func evictOldestSNMP(pending map[snmpKey]*SNMPExchange) {
	var selected snmpKey
	var oldest *SNMPExchange
	for key, value := range pending {
		if oldest == nil || value.RequestedAt.Before(oldest.RequestedAt) {
			selected, oldest = key, value
		}
	}
	delete(pending, selected)
}
