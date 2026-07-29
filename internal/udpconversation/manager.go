package udpconversation

import (
	"container/list"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

const (
	defaultMaxActive                 = 100_000
	defaultMaxPacketsPerConversation = 100_000
)

type ManagerConfig struct {
	Disabled                  bool
	MaxActive                 int
	MaxPacketsPerConversation uint64
	IdleTimeout               time.Duration
}

type Direction string

const (
	DirectionAToB Direction = "a_to_b"
	DirectionBToA Direction = "b_to_a"
)

// ParseContext is supplemental metadata for UDP protocol parsers. Parsers must
// continue to accept packets without it.
type ParseContext struct {
	ConversationID string
	Direction      Direction
	PacketIndex    uint64
	StartedAt      time.Time

	// RTTMillis is a best-effort request/response latency estimate. It is set
	// when packet direction changes and remains zero when no estimate exists.
	RTTMillis float64
}

// ContextualPacket is published after conversation accounting and retains the
// original packet unchanged for existing protocol parsers.
type ContextualPacket struct {
	Packet  core.Packet
	Context ParseContext
}

type Manager struct {
	mu            sync.RWMutex
	conversations map[Key]*Conversation
	lru           *list.List
	lruNodes      map[Key]*list.Element
	config        ManagerConfig
	stats         ManagerStats
}

// NewManager retains the original constructor while enabling all protections.
func NewManager(maxActive int) *Manager {
	return NewManagerWithConfig(ManagerConfig{MaxActive: maxActive})
}

func NewManagerWithConfig(config ManagerConfig) *Manager {
	if config.MaxActive <= 0 {
		config.MaxActive = defaultMaxActive
	}
	if config.MaxPacketsPerConversation == 0 {
		config.MaxPacketsPerConversation = defaultMaxPacketsPerConversation
	}
	return &Manager{
		conversations: make(map[Key]*Conversation),
		lru:           list.New(),
		lruNodes:      make(map[Key]*list.Element),
		config:        config,
	}
}

// GetOrCreate returns a snapshot of the requested conversation. When capacity
// is full, the least-recently-seen conversation is evicted first.
func (m *Manager) GetOrCreate(key Key) *Conversation {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	if conversation := m.conversations[key]; conversation != nil {
		return cloneConversation(conversation)
	}
	m.makeRoomLocked()
	conversation := newConversation(key, now)
	m.conversations[key] = conversation
	m.lruNodes[key] = m.lru.PushBack(key)
	m.stats.Created++
	return cloneConversation(conversation)
}

// Observe records one UDP packet. It returns a snapshot and false only when
// the packet is not UDP or the per-conversation packet limit was reached.
func (m *Manager) Observe(packet core.Packet) (*Conversation, bool) {
	conversation, _, accepted := m.ObserveWithContext(packet)
	return conversation, accepted
}

// ObserveWithContext records one UDP packet and returns the supplemental
// parser context generated for it.
func (m *Manager) ObserveWithContext(packet core.Packet) (*Conversation, ParseContext, bool) {
	if packet.L4Protocol != "UDP" {
		return nil, ParseContext{}, false
	}
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	bytes := packet.Length
	if bytes < 0 {
		bytes = 0
	}

	key := NewKey(packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
	m.mu.Lock()
	defer m.mu.Unlock()

	conversation := m.conversations[key]
	if conversation == nil {
		m.makeRoomLocked()
		conversation = newConversation(key, now)
		m.conversations[key] = conversation
		m.lruNodes[key] = m.lru.PushBack(key)
		m.stats.Created++
	} else {
		m.stats.Updated++
		if node := m.lruNodes[key]; node != nil {
			m.lru.MoveToBack(node)
		}
	}

	if now.After(conversation.LastSeenAt) {
		conversation.LastSeenAt = now
	}
	if conversation.Packets >= m.config.MaxPacketsPerConversation {
		m.stats.Dropped++
		return cloneConversation(conversation), contextFor(conversation, key, packet, now), false
	}

	direction := packetDirection(key, packet)
	rttMillis := 0.0
	if conversation.Packets > 0 &&
		conversation.lastDirection != "" &&
		conversation.lastDirection != direction &&
		!now.Before(conversation.lastPacketAt) {
		rttMillis = float64(now.Sub(conversation.lastPacketAt)) / float64(time.Millisecond)
	}
	conversation.Packets++
	conversation.Bytes += uint64(bytes)
	if direction == DirectionAToB {
		conversation.DirectionA++
		conversation.DirectionABytes += uint64(bytes)
	} else {
		conversation.DirectionB++
		conversation.DirectionBBytes += uint64(bytes)
	}
	m.stats.TotalPackets++
	m.stats.TotalBytes += uint64(bytes)
	conversation.lastDirection = direction
	conversation.lastPacketAt = now
	conversation.Protocol = classifyProtocol(packet.SrcPort, packet.DstPort)

	context := ParseContext{
		ConversationID: conversation.ID,
		Direction:      direction,
		PacketIndex:    conversation.Packets,
		StartedAt:      conversation.StartedAt,
		RTTMillis:      rttMillis,
	}
	return cloneConversation(conversation), context, true
}

// Get returns an immutable snapshot suitable for concurrent callers.
func (m *Manager) Get(key Key) (*Conversation, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conversation := m.conversations[key]
	if conversation == nil {
		return nil, false
	}
	return cloneConversation(conversation), true
}

func (m *Manager) Conversations() []Conversation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Conversation, 0, len(m.conversations))
	for _, conversation := range m.conversations {
		result = append(result, *conversation)
	}
	return result
}

func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats := m.stats
	stats.Active = uint64(len(m.conversations))
	return stats
}

func (m *Manager) Telemetry(now time.Time, unmatchedResponses, requestTimeouts uint64, averageRTTMillis float64) Telemetry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var totalDuration time.Duration
	for _, conversation := range m.conversations {
		if !now.Before(conversation.StartedAt) {
			totalDuration += now.Sub(conversation.StartedAt)
		}
	}
	averageDuration := 0.0
	if len(m.conversations) > 0 {
		averageDuration = float64(totalDuration) / float64(len(m.conversations)) / float64(time.Millisecond)
	}
	return Telemetry{
		UDPConversationsActive:       uint64(len(m.conversations)),
		UDPConversationsCreatedTotal: m.stats.Created,
		UDPConversationsExpiredTotal: m.stats.Expired,
		UDPConversationsEvictedTotal: m.stats.Evicted,
		UDPPacketsTotal:              m.stats.TotalPackets,
		UDPBytesTotal:                m.stats.TotalBytes,
		UDPUnmatchedResponsesTotal:   unmatchedResponses,
		UDPRequestTimeoutsTotal:      requestTimeouts,
		UDPAverageDuration:           averageDuration,
		UDPAverageRTT:                averageRTTMillis,
	}
}

func (m *Manager) makeRoomLocked() {
	if m.config.MaxActive <= 0 || len(m.conversations) < m.config.MaxActive {
		return
	}

	if oldest := m.lru.Front(); oldest != nil {
		oldestKey := oldest.Value.(Key)
		delete(m.conversations, oldestKey)
		delete(m.lruNodes, oldestKey)
		m.lru.Remove(oldest)
		m.stats.Evicted++
	}
}

func newConversation(key Key, now time.Time) *Conversation {
	return &Conversation{
		ID:         conversationID(key),
		Key:        key,
		Protocol:   "UDP",
		StartedAt:  now,
		LastSeenAt: now,
	}
}

func conversationID(key Key) string {
	return key.EndpointAIP + ":" + fmtPort(key.EndpointAPort) + "-" +
		key.EndpointBIP + ":" + fmtPort(key.EndpointBPort) + "-udp"
}

func classifyProtocol(source, destination uint16) string {
	for _, port := range []uint16{source, destination} {
		switch port {
		case 53:
			return "dns"
		case 67, 68:
			return "dhcp"
		case 123:
			return "ntp"
		case 161, 162:
			return "snmp"
		case 5060:
			return "sip"
		case 443, 5684:
			return "dtls"
		case 1194:
			return "openvpn"
		case 6969:
			return "bittorrent"
		}
	}
	return "udp"
}

func fmtPort(port uint16) string {
	const digits = "0123456789"
	if port == 0 {
		return "0"
	}
	var buffer [5]byte
	index := len(buffer)
	for port > 0 {
		index--
		buffer[index] = digits[port%10]
		port /= 10
	}
	return string(buffer[index:])
}

func cloneConversation(conversation *Conversation) *Conversation {
	copy := *conversation
	return &copy
}

func packetDirection(key Key, packet core.Packet) Direction {
	if key.isDirectionA(packet.SrcIP, packet.SrcPort) {
		return DirectionAToB
	}
	return DirectionBToA
}

func contextFor(conversation *Conversation, key Key, packet core.Packet, now time.Time) ParseContext {
	context := ParseContext{
		ConversationID: conversation.ID,
		Direction:      packetDirection(key, packet),
		PacketIndex:    conversation.Packets,
		StartedAt:      conversation.StartedAt,
	}
	if conversation.lastDirection != "" &&
		conversation.lastDirection != context.Direction &&
		!now.Before(conversation.lastPacketAt) {
		context.RTTMillis = float64(now.Sub(conversation.lastPacketAt)) / float64(time.Millisecond)
	}
	return context
}
