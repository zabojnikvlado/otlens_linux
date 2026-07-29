package udpconversation

import (
	"container/list"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

const (
	defaultMaxActive                 = 100_000
	defaultMaxPacketsPerConversation = 100_000
	managerShardCount                = 256
)

type ManagerConfig struct {
	Disabled                  bool
	SensorID                  string
	MaxActive                 int
	MaxPacketsPerConversation uint64
	IdleTimeout               time.Duration
}

type Direction string

const (
	DirectionAToB Direction = "a_to_b"
	DirectionBToA Direction = "b_to_a"
)

type ParseContext struct {
	ConversationID string
	FlowID         string
	SensorID       string
	Direction      Direction
	PacketIndex    uint64
	StartedAt      time.Time
	RTTMillis      float64
}

type ContextualPacket struct {
	Packet  core.Packet
	Context ParseContext
}

type managerShard struct {
	mu            sync.RWMutex
	conversations map[Key]*Conversation
	lru           *list.List
	lruNodes      map[Key]*list.Element
}

type managerCounters struct {
	active, created, updated, expired, evicted, dropped, packets, bytes atomic.Uint64
}

type Manager struct {
	shards     [managerShardCount]managerShard
	shardCount int
	config     ManagerConfig
	stats      managerCounters
}

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
	shardCount := managerShardCount
	// Tiny test/embedded limits use one shard so capacity is not fragmented.
	// Production-sized tables use all 256 shards.
	if config.MaxActive < managerShardCount*16 {
		shardCount = 1
	}
	manager := &Manager{config: config, shardCount: shardCount}
	for index := 0; index < shardCount; index++ {
		manager.shards[index] = managerShard{
			conversations: make(map[Key]*Conversation),
			lru:           list.New(),
			lruNodes:      make(map[Key]*list.Element),
		}
	}
	return manager
}

func (m *Manager) GetOrCreate(key Key) *Conversation {
	now := time.Now()
	shard := m.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if conversation := shard.conversations[key]; conversation != nil {
		return cloneConversation(conversation)
	}
	canInsert, _ := m.prepareSlotLocked(shard)
	if !canInsert {
		m.stats.dropped.Add(1)
		return nil
	}
	conversation := m.newConversation(key, now, flowID(key))
	shard.conversations[key] = conversation
	shard.lruNodes[key] = shard.lru.PushBack(key)
	m.stats.created.Add(1)
	return cloneConversation(conversation)
}

func (m *Manager) Observe(packet core.Packet) (*Conversation, bool) {
	conversation, _, accepted := m.ObserveWithContext(packet)
	return conversation, accepted
}

func (m *Manager) ObserveWithContext(packet core.Packet) (*Conversation, ParseContext, bool) {
	if packet.L4Protocol != "UDP" {
		return nil, ParseContext{}, false
	}
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	size := packet.Length
	if size < 0 {
		size = 0
	}
	key := NewKey(packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
	shard := m.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	conversation := shard.conversations[key]
	if conversation == nil {
		canInsert, _ := m.prepareSlotLocked(shard)
		if !canInsert {
			m.stats.dropped.Add(1)
			return nil, ParseContext{}, false
		}
		conversation = m.newConversation(key, now, packetFlowID(packet))
		shard.conversations[key] = conversation
		shard.lruNodes[key] = shard.lru.PushBack(key)
		m.stats.created.Add(1)
	} else {
		m.stats.updated.Add(1)
		if node := shard.lruNodes[key]; node != nil {
			shard.lru.MoveToBack(node)
		}
	}
	if now.After(conversation.LastSeenAt) {
		conversation.LastSeenAt = now
	}
	if conversation.Packets >= m.config.MaxPacketsPerConversation {
		m.stats.dropped.Add(1)
		return cloneConversation(conversation), m.contextFor(conversation, key, packet, now), false
	}

	direction := packetDirection(key, packet)
	rttMillis := 0.0
	if conversation.Packets > 0 && conversation.lastDirection != "" &&
		conversation.lastDirection != direction && !now.Before(conversation.lastPacketAt) {
		rttMillis = float64(now.Sub(conversation.lastPacketAt)) / float64(time.Millisecond)
	}
	conversation.Packets++
	conversation.Bytes += uint64(size)
	if direction == DirectionAToB {
		conversation.DirectionA++
		conversation.DirectionABytes += uint64(size)
	} else {
		conversation.DirectionB++
		conversation.DirectionBBytes += uint64(size)
	}
	conversation.lastDirection = direction
	conversation.lastPacketAt = now
	conversation.Protocol = classifyProtocol(packet.SrcPort, packet.DstPort)
	m.stats.packets.Add(1)
	m.stats.bytes.Add(uint64(size))

	context := m.contextFor(conversation, key, packet, now)
	context.Direction = direction
	context.RTTMillis = rttMillis
	return cloneConversation(conversation), context, true
}

func (m *Manager) Get(key Key) (*Conversation, bool) {
	shard := m.shardFor(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	conversation := shard.conversations[key]
	if conversation == nil {
		return nil, false
	}
	return cloneConversation(conversation), true
}

func (m *Manager) Conversations() []Conversation {
	result := make([]Conversation, 0, int(m.stats.active.Load()))
	for index := 0; index < m.shardCount; index++ {
		shard := &m.shards[index]
		shard.mu.RLock()
		for _, conversation := range shard.conversations {
			result = append(result, *conversation)
		}
		shard.mu.RUnlock()
	}
	return result
}

func (m *Manager) Stats() ManagerStats {
	return ManagerStats{
		Active:       m.stats.active.Load(),
		Created:      m.stats.created.Load(),
		Updated:      m.stats.updated.Load(),
		Expired:      m.stats.expired.Load(),
		Evicted:      m.stats.evicted.Load(),
		Dropped:      m.stats.dropped.Load(),
		TotalPackets: m.stats.packets.Load(),
		TotalBytes:   m.stats.bytes.Load(),
	}
}

func (m *Manager) Telemetry(now time.Time, unmatchedResponses, requestTimeouts uint64, averageRTTMillis float64) Telemetry {
	var totalDuration time.Duration
	var active uint64
	for index := 0; index < m.shardCount; index++ {
		shard := &m.shards[index]
		shard.mu.RLock()
		active += uint64(len(shard.conversations))
		for _, conversation := range shard.conversations {
			if !now.Before(conversation.StartedAt) {
				totalDuration += now.Sub(conversation.StartedAt)
			}
		}
		shard.mu.RUnlock()
	}
	averageDuration := 0.0
	if active > 0 {
		averageDuration = float64(totalDuration) / float64(active) / float64(time.Millisecond)
	}
	stats := m.Stats()
	return Telemetry{
		UDPConversationsActive:       active,
		UDPConversationsCreatedTotal: stats.Created,
		UDPConversationsExpiredTotal: stats.Expired,
		UDPConversationsEvictedTotal: stats.Evicted,
		UDPPacketsTotal:              stats.TotalPackets,
		UDPBytesTotal:                stats.TotalBytes,
		UDPUnmatchedResponsesTotal:   unmatchedResponses,
		UDPRequestTimeoutsTotal:      requestTimeouts,
		UDPAverageDuration:           averageDuration,
		UDPAverageRTT:                averageRTTMillis,
	}
}

func (m *Manager) prepareSlotLocked(shard *managerShard) (canInsert, reserved bool) {
	for {
		active := m.stats.active.Load()
		if active >= uint64(m.config.MaxActive) {
			break
		}
		if m.stats.active.CompareAndSwap(active, active+1) {
			return true, true
		}
	}
	if oldest := shard.lru.Front(); oldest != nil {
		key := oldest.Value.(Key)
		delete(shard.conversations, key)
		delete(shard.lruNodes, key)
		shard.lru.Remove(oldest)
		m.stats.evicted.Add(1)
		return true, false
	}
	return false, false
}

func (m *Manager) shardFor(key Key) *managerShard {
	return &m.shards[hashKey(key)%uint32(m.shardCount)]
}

func hashKey(key Key) uint32 {
	hash := uint32(2166136261)
	add := func(value byte) { hash = (hash ^ uint32(value)) * 16777619 }
	for index := 0; index < len(key.EndpointAIP); index++ {
		add(key.EndpointAIP[index])
	}
	add(byte(key.EndpointAPort >> 8))
	add(byte(key.EndpointAPort))
	for index := 0; index < len(key.EndpointBIP); index++ {
		add(key.EndpointBIP[index])
	}
	add(byte(key.EndpointBPort >> 8))
	add(byte(key.EndpointBPort))
	return hash
}

func (m *Manager) newConversation(key Key, now time.Time, flowID string) *Conversation {
	return &Conversation{ID: conversationID(key), FlowID: flowID, SensorID: m.config.SensorID, Key: key, Protocol: "udp", StartedAt: now, LastSeenAt: now}
}

func conversationID(key Key) string {
	return key.EndpointAIP + ":" + fmtPort(key.EndpointAPort) + "-" +
		key.EndpointBIP + ":" + fmtPort(key.EndpointBPort) + "-udp"
}

func flowID(key Key) string {
	a := fmt.Sprintf("%s:%d", key.EndpointAIP, key.EndpointAPort)
	b := fmt.Sprintf("%s:%d", key.EndpointBIP, key.EndpointBPort)
	if a > b {
		a, b = b, a
	}
	return "UDP|" + a + "|" + b
}

func packetFlowID(packet core.Packet) string {
	a := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
	b := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)
	if a > b {
		a, b = b, a
	}
	return "UDP|" + a + "|" + b
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
	return fmt.Sprintf("%d", port)
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

func (m *Manager) contextFor(conversation *Conversation, key Key, packet core.Packet, now time.Time) ParseContext {
	context := ParseContext{
		ConversationID: conversation.ID,
		FlowID:         conversation.FlowID,
		SensorID:       conversation.SensorID,
		Direction:      packetDirection(key, packet),
		PacketIndex:    conversation.Packets,
		StartedAt:      conversation.StartedAt,
	}
	if conversation.lastDirection != "" && conversation.lastDirection != context.Direction &&
		!now.Before(conversation.lastPacketAt) {
		context.RTTMillis = float64(now.Sub(conversation.lastPacketAt)) / float64(time.Millisecond)
	}
	return context
}
