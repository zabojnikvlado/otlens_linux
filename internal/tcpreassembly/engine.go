package tcpreassembly

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/streamproto"
)

type Config struct {
	Enabled               bool
	MaxConnections        int
	MaxBufferPerDirection int
	MaxTotalBuffer        int
	IdleTimeout           time.Duration
	ClosedTimeout         time.Duration
	MaxOutOfOrderSegments int
	MaxSequenceGap        uint32
	GapRecoveryTimeout    time.Duration
	ShardCount            int
	OverlapPolicy         string // first_seen or last_seen
	MaxConnectionsPerIP   int
	SynTimeout            time.Duration
	LongLivedIdleTimeout  time.Duration
}

type segment struct {
	seq  uint32
	data []byte
	ts   time.Time
}
type direction struct {
	initialized        bool
	next               uint32
	pending            map[uint32]segment
	buffered           int
	midstream          bool
	gapped             bool
	gapSince           time.Time
	protocol           string
	protocolConfidence uint8
	packets            uint64
	bytes              uint64
	finSeen            bool
}
type connection struct {
	id                 string
	aIP, bIP           string
	aPort, bPort       uint16
	a2b, b2a           direction
	createdAt          time.Time
	lastSeen           time.Time
	closedAt           time.Time
	state              string
	synSeen            bool
	synAckSeen         bool
	rstSeen            bool
	seenA2B            bool
	seenB2A            bool
	midstream          bool
	asymmetricReported bool
}
type shard struct {
	mu       sync.Mutex
	conns    map[string]*connection
	buffered int
}

type stats struct {
	active, peakActive, buffered, bufferedHighWater                                                                                          int64
	opened, closed, segments, bytes, chunks, emitted, outOfOrder, retransmitted, overlaps, overlapConflicts, gapRecoveries, evicted, dropped uint64
	duplicates, timedOut, resets, perIPDrops, durationNanos                                                                                  uint64
	midstream, asymmetric, lowConfidence                                                                                                     uint64
}

type Engine struct {
	bus           *core.EventBus
	cfg           Config
	shards        []shard
	pool          sync.Pool
	ipMu          sync.Mutex
	ipConnections map[string]int
	st            stats
	stop          chan struct{}
	running       atomic.Bool
}

func New(bus *core.EventBus, cfg Config) *Engine {
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 50000
	}
	if cfg.MaxBufferPerDirection <= 0 {
		cfg.MaxBufferPerDirection = 4 << 20
	}
	if cfg.MaxTotalBuffer <= 0 {
		cfg.MaxTotalBuffer = 512 << 20
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.ClosedTimeout <= 0 {
		cfg.ClosedTimeout = 15 * time.Second
	}
	if cfg.MaxOutOfOrderSegments <= 0 {
		cfg.MaxOutOfOrderSegments = 256
	}
	if cfg.MaxSequenceGap == 0 {
		cfg.MaxSequenceGap = 16 << 20
	}
	if cfg.GapRecoveryTimeout <= 0 {
		cfg.GapRecoveryTimeout = 2 * time.Second
	}
	if cfg.ShardCount <= 0 {
		cfg.ShardCount = 32
	}
	if cfg.OverlapPolicy != "last_seen" {
		cfg.OverlapPolicy = "first_seen"
	}
	if cfg.MaxConnectionsPerIP <= 0 {
		cfg.MaxConnectionsPerIP = 4096
	}
	if cfg.SynTimeout <= 0 {
		cfg.SynTimeout = 30 * time.Second
	}
	if cfg.LongLivedIdleTimeout <= 0 {
		cfg.LongLivedIdleTimeout = 15 * time.Minute
	}
	e := &Engine{bus: bus, cfg: cfg, shards: make([]shard, cfg.ShardCount), stop: make(chan struct{}), ipConnections: map[string]int{}}
	for i := range e.shards {
		e.shards[i].conns = map[string]*connection{}
	}
	e.pool.New = func() any { b := make([]byte, 0, 2048); return &b }
	return e
}
func (e *Engine) Start() {
	if !e.cfg.Enabled {
		return
	}
	e.running.Store(true)
	ch := e.bus.Subscribe(core.EventPacketParsed)
	go func() {
		for ev := range ch {
			if p, ok := ev.Data.(core.Packet); ok {
				e.Push(p)
			}
		}
	}()
	go e.cleanupLoop()
}
func (e *Engine) Stop() {
	e.running.Store(false)
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
}
func canonical(p core.Packet) (string, bool) {
	a := fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)
	b := fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)
	if a <= b {
		return a + "-" + b, true
	}
	return b + "-" + a, false
}
func hasFlag(flags, want string) bool {
	for _, f := range strings.Split(flags, ",") {
		if f == want {
			return true
		}
	}
	return false
}
func hash(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
func (e *Engine) shardFor(id string) *shard { return &e.shards[int(hash(id)%uint32(len(e.shards)))] }
func (e *Engine) copyBytes(data []byte) []byte {
	p := e.pool.Get().(*[]byte)
	b := *p
	if cap(b) < len(data) {
		b = make([]byte, len(data))
	} else {
		b = b[:len(data)]
	}
	copy(b, data)
	return b
}
func (e *Engine) release(b []byte) {
	if cap(b) > 64<<10 {
		return
	}
	b = b[:0]
	e.pool.Put(&b)
}

func updateMax(dst *int64, value int64) {
	for {
		old := atomic.LoadInt64(dst)
		if value <= old || atomic.CompareAndSwapInt64(dst, old, value) {
			return
		}
	}
}

func (e *Engine) canTrackIPs(a, b string) bool {
	e.ipMu.Lock()
	defer e.ipMu.Unlock()
	if e.ipConnections[a] >= e.cfg.MaxConnectionsPerIP || e.ipConnections[b] >= e.cfg.MaxConnectionsPerIP {
		return false
	}
	e.ipConnections[a]++
	if b != a {
		e.ipConnections[b]++
	}
	return true
}

func (e *Engine) releaseIPs(a, b string) {
	e.ipMu.Lock()
	defer e.ipMu.Unlock()
	for _, ip := range []string{a, b} {
		if ip == "" || (ip == b && a == b) {
			continue
		}
		if e.ipConnections[ip] <= 1 {
			delete(e.ipConnections, ip)
		} else {
			e.ipConnections[ip]--
		}
	}
}

func (e *Engine) Push(p core.Packet) {
	if p.L4Protocol != "TCP" {
		return
	}
	atomic.AddUint64(&e.st.segments, 1)
	atomic.AddUint64(&e.st.bytes, uint64(len(p.AppPayload)))
	id, forward := canonical(p)
	s := e.shardFor(id)
	s.mu.Lock()
	c := s.conns[id]
	if c == nil {
		if !e.canTrackIPs(p.SrcIP, p.DstIP) {
			atomic.AddUint64(&e.st.perIPDrops, 1)
			atomic.AddUint64(&e.st.dropped, 1)
			s.mu.Unlock()
			return
		}
		if atomic.LoadInt64(&e.st.active) >= int64(e.cfg.MaxConnections) {
			e.evictOldestLocked(s, "connection_limit")
		}
		startedWithSYN := hasFlag(p.TCPFlags, "SYN")
		c = &connection{id: id, createdAt: p.Timestamp, lastSeen: p.Timestamp, state: "observed", midstream: !startedWithSYN}
		if c.midstream {
			atomic.AddUint64(&e.st.midstream, 1)
		}
		if forward {
			c.aIP, c.aPort, c.bIP, c.bPort = p.SrcIP, p.SrcPort, p.DstIP, p.DstPort
		} else {
			c.aIP, c.aPort, c.bIP, c.bPort = p.DstIP, p.DstPort, p.SrcIP, p.SrcPort
		}
		c.a2b.pending = map[uint32]segment{}
		c.b2a.pending = map[uint32]segment{}
		s.conns[id] = c
		active := atomic.AddInt64(&e.st.active, 1)
		updateMax(&e.st.peakActive, active)
		atomic.AddUint64(&e.st.opened, 1)
		e.publishLifecycle(c, "stream_open", "")
	}
	c.lastSeen = p.Timestamp
	d := &c.a2b
	if forward {
		c.seenA2B = true
	} else {
		d = &c.b2a
		c.seenB2A = true
	}
	d.packets++
	d.bytes += uint64(len(p.AppPayload))
	if hasFlag(p.TCPFlags, "SYN") {
		c.synSeen = true
		if hasFlag(p.TCPFlags, "ACK") {
			c.synAckSeen = true
			c.state = "established"
		} else {
			c.state = "syn_seen"
		}
	} else if hasFlag(p.TCPFlags, "ACK") && c.state != "established" {
		c.state = "established"
	}
	seq := p.TCPSeq
	if hasFlag(p.TCPFlags, "SYN") {
		seq++
	}
	chunks := e.acceptLocked(s, c, d, seq, p.AppPayload, p.Timestamp, forward)
	if hasFlag(p.TCPFlags, "FIN") {
		d.finSeen = true
		c.closedAt = p.Timestamp
		if c.a2b.finSeen && c.b2a.finSeen {
			c.state = "closed"
		} else {
			c.state = "half_closed"
		}
		e.publishLifecycle(c, "stream_close", "fin")
	}
	if hasFlag(p.TCPFlags, "RST") {
		c.rstSeen = true
		c.state = "reset"
		c.closedAt = p.Timestamp
		atomic.AddUint64(&e.st.resets, 1)
		e.publishLifecycle(c, "stream_reset", "rst")
	}
	s.mu.Unlock()
	for _, ch := range chunks {
		e.bus.Publish(core.Event{Type: core.EventTCPStreamData, Timestamp: ch.Timestamp, Data: ch})
	}
}
func seqLess(a, b uint32) bool       { return int32(a-b) < 0 }
func seqDistance(a, b uint32) uint32 { return b - a }
func overlapConflict(existing, new []byte) bool {
	n := len(existing)
	if len(new) < n {
		n = len(new)
	}
	for i := 0; i < n; i++ {
		if existing[i] != new[i] {
			return true
		}
	}
	return false
}
func (e *Engine) acceptLocked(s *shard, c *connection, d *direction, seq uint32, data []byte, ts time.Time, forward bool) []core.TCPStreamChunk {
	if len(data) == 0 {
		return nil
	}
	if !d.initialized {
		d.initialized = true
		d.next = seq
		d.midstream = c.midstream
	}
	overlap := false
	if seqLess(seq, d.next) {
		skip := uint32(d.next - seq)
		atomic.AddUint64(&e.st.retransmitted, uint64(minU32(skip, uint32(len(data)))))
		if skip >= uint32(len(data)) {
			atomic.AddUint64(&e.st.duplicates, 1)
			return nil
		}
		data = data[skip:]
		seq = d.next
		overlap = true
		atomic.AddUint64(&e.st.overlaps, 1)
	}
	if seq != d.next {
		gap := seqDistance(d.next, seq)
		if gap > e.cfg.MaxSequenceGap || len(d.pending) >= e.cfg.MaxOutOfOrderSegments || d.buffered+len(data) > e.cfg.MaxBufferPerDirection || atomic.LoadInt64(&e.st.buffered)+int64(len(data)) > int64(e.cfg.MaxTotalBuffer) {
			d.gapped = true
			atomic.AddUint64(&e.st.dropped, 1)
			e.publishLifecycle(c, "stream_truncated", "reassembly_limit")
			return nil
		}
		if old, exists := d.pending[seq]; exists {
			atomic.AddUint64(&e.st.overlaps, 1)
			if overlapConflict(old.data, data) {
				atomic.AddUint64(&e.st.overlapConflicts, 1)
			}
			if e.cfg.OverlapPolicy == "last_seen" {
				s.buffered -= len(old.data)
				d.buffered -= len(old.data)
				atomic.AddInt64(&e.st.buffered, -int64(len(old.data)))
				e.release(old.data)
				cp := e.copyBytes(data)
				d.pending[seq] = segment{seq: seq, data: cp, ts: ts}
				s.buffered += len(cp)
				d.buffered += len(cp)
				buffered := atomic.AddInt64(&e.st.buffered, int64(len(cp)))
				updateMax(&e.st.bufferedHighWater, buffered)
			}
			return nil
		}
		cp := e.copyBytes(data)
		d.pending[seq] = segment{seq: seq, data: cp, ts: ts}
		d.buffered += len(cp)
		s.buffered += len(cp)
		buffered := atomic.AddInt64(&e.st.buffered, int64(len(cp)))
		updateMax(&e.st.bufferedHighWater, buffered)
		atomic.AddUint64(&e.st.outOfOrder, 1)
		if d.gapSince.IsZero() {
			d.gapSince = ts
		}
		return nil
	}
	return e.emitContiguousLocked(s, c, d, data, ts, forward, 0, overlap)
}
func (e *Engine) emitContiguousLocked(s *shard, c *connection, d *direction, data []byte, ts time.Time, forward bool, gapBefore uint32, overlap bool) []core.TCPStreamChunk {
	var out []core.TCPStreamChunk
	emit := func(b []byte, t time.Time, gap uint32) {
		if len(b) == 0 {
			return
		}
		srcIP, dstIP := c.aIP, c.bIP
		srcPort, dstPort := c.aPort, c.bPort
		if !forward {
			srcIP, dstIP = c.bIP, c.aIP
			srcPort, dstPort = c.bPort, c.aPort
		}
		proto := d.protocol
		confidence := d.protocolConfidence
		if proto == "" || proto == "unknown" || confidence < 80 {
			result := streamproto.DetectResult(b)
			proto = result.Protocol
			confidence = result.Confidence
			if proto != "unknown" && confidence >= d.protocolConfidence {
				d.protocol = proto
				d.protocolConfidence = confidence
			}
		}
		if proto != "unknown" && confidence < 80 {
			atomic.AddUint64(&e.st.lowConfidence, 1)
		}
		cp := append([]byte(nil), b...)
		out = append(out, core.TCPStreamChunk{ConnectionID: c.id, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Timestamp: t, Data: cp, Midstream: d.midstream, Gapped: d.gapped, GapBefore: gap, Overlap: overlap, Protocol: proto, ProtocolConfidence: confidence, Asymmetric: !(c.seenA2B && c.seenB2A)})
		d.next += uint32(len(b))
		atomic.AddUint64(&e.st.chunks, 1)
		atomic.AddUint64(&e.st.emitted, uint64(len(b)))
	}
	emit(data, ts, gapBefore)
	for {
		sg, ok := d.pending[d.next]
		if !ok {
			break
		}
		delete(d.pending, d.next)
		d.buffered -= len(sg.data)
		s.buffered -= len(sg.data)
		atomic.AddInt64(&e.st.buffered, -int64(len(sg.data)))
		emit(sg.data, sg.ts, 0)
		e.release(sg.data)
	}
	if len(d.pending) == 0 {
		d.gapSince = time.Time{}
	}
	return out
}
func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func (e *Engine) cleanupLoop() {
	t := time.NewTicker(time.Second)
	metrics := time.NewTicker(15 * time.Second)
	defer t.Stop()
	defer metrics.Stop()
	for {
		select {
		case now := <-t.C:
			e.cleanup(now)
		case now := <-metrics.C:
			e.bus.Publish(core.Event{Type: core.EventTCPReassemblyStats, Timestamp: now, Data: e.Stats()})
		case <-e.stop:
			return
		}
	}
}
func (e *Engine) cleanup(now time.Time) {
	for i := range e.shards {
		s := &e.shards[i]
		var publish []core.TCPStreamChunk
		s.mu.Lock()
		for id, c := range s.conns {
			if !c.asymmetricReported && now.Sub(c.createdAt) >= 5*time.Second && !(c.seenA2B && c.seenB2A) {
				c.asymmetricReported = true
				atomic.AddUint64(&e.st.asymmetric, 1)
				e.publishLifecycle(c, "stream_asymmetric", "one_direction_only")
			}
			publish = append(publish, e.recoverDirectionLocked(s, c, &c.a2b, now, true)...)
			publish = append(publish, e.recoverDirectionLocked(s, c, &c.b2a, now, false)...)
			timeout := e.connectionTimeout(c)
			reason := "idle_timeout"
			if !c.closedAt.IsZero() {
				timeout = e.cfg.ClosedTimeout
				reason = "closed"
				if c.rstSeen {
					reason = "reset"
				}
				if now.Sub(c.closedAt) < timeout {
					continue
				}
			} else if now.Sub(c.lastSeen) < timeout {
				continue
			}
			if reason == "idle_timeout" {
				atomic.AddUint64(&e.st.timedOut, 1)
				e.publishLifecycle(c, "stream_timeout", reason)
			}
			e.removeLocked(s, id, c, reason)
		}
		s.mu.Unlock()
		for _, ch := range publish {
			e.bus.Publish(core.Event{Type: core.EventTCPStreamData, Timestamp: ch.Timestamp, Data: ch})
		}
	}
}
func (e *Engine) recoverDirectionLocked(s *shard, c *connection, d *direction, now time.Time, forward bool) []core.TCPStreamChunk {
	if d.gapSince.IsZero() || now.Sub(d.gapSince) < e.cfg.GapRecoveryTimeout || len(d.pending) == 0 {
		return nil
	}
	seqs := make([]uint32, 0, len(d.pending))
	for seq := range d.pending {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqLess(seqs[i], seqs[j]) })
	first := seqs[0]
	gap := first - d.next
	d.next = first
	d.gapped = true
	d.gapSince = time.Time{}
	atomic.AddUint64(&e.st.gapRecoveries, 1)
	e.publishLifecycle(c, "stream_gap", "gap_recovery")
	sg := d.pending[first]
	delete(d.pending, first)
	d.buffered -= len(sg.data)
	s.buffered -= len(sg.data)
	atomic.AddInt64(&e.st.buffered, -int64(len(sg.data)))
	out := e.emitContiguousLocked(s, c, d, sg.data, sg.ts, forward, gap, false)
	e.release(sg.data)
	return out
}
func (e *Engine) connectionTimeout(c *connection) time.Duration {
	if c.state == "syn_seen" && !c.synAckSeen {
		return e.cfg.SynTimeout
	}
	proto := c.a2b.protocol
	if proto == "" || proto == "unknown" {
		proto = c.b2a.protocol
	}
	if proto == "modbus" || proto == "s7" || proto == "dnp3" || proto == "opcua" || c.aPort == 502 || c.bPort == 502 || c.aPort == 102 || c.bPort == 102 || c.aPort == 2404 || c.bPort == 2404 || c.aPort == 4840 || c.bPort == 4840 {
		return e.cfg.LongLivedIdleTimeout
	}
	return e.cfg.IdleTimeout
}

func (e *Engine) evictOldestLocked(s *shard, reason string) {
	if len(s.conns) == 0 {
		return
	}
	ids := make([]string, 0, len(s.conns))
	for id := range s.conns {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return s.conns[ids[i]].lastSeen.Before(s.conns[ids[j]].lastSeen) })
	e.removeLocked(s, ids[0], s.conns[ids[0]], reason)
	atomic.AddUint64(&e.st.evicted, 1)
}
func (e *Engine) removeLocked(s *shard, id string, c *connection, reason string) {
	for _, d := range []*direction{&c.a2b, &c.b2a} {
		for _, sg := range d.pending {
			e.release(sg.data)
		}
		s.buffered -= d.buffered
		atomic.AddInt64(&e.st.buffered, -int64(d.buffered))
	}
	delete(s.conns, id)
	e.releaseIPs(c.aIP, c.bIP)
	atomic.AddInt64(&e.st.active, -1)
	atomic.AddUint64(&e.st.closed, 1)
	if !c.createdAt.IsZero() && !c.lastSeen.Before(c.createdAt) {
		atomic.AddUint64(&e.st.durationNanos, uint64(c.lastSeen.Sub(c.createdAt)))
	}
	c.state = "closed"
	e.publishLifecycle(c, "stream_closed", reason)
}
func (e *Engine) publishLifecycle(c *connection, typ, reason string) {
	proto := c.a2b.protocol
	if proto == "" {
		proto = c.b2a.protocol
	}
	ev := core.TCPStreamEvent{ConnectionID: c.id, Type: typ, Reason: reason, State: c.state, Timestamp: c.lastSeen, SrcIP: c.aIP, DstIP: c.bIP, SrcPort: c.aPort, DstPort: c.bPort, Buffered: c.a2b.buffered + c.b2a.buffered, Protocol: proto, PacketsA2B: c.a2b.packets, PacketsB2A: c.b2a.packets, BytesA2B: c.a2b.bytes, BytesB2A: c.b2a.bytes}
	e.bus.Publish(core.Event{Type: core.EventTCPStreamLifecycle, Timestamp: ev.Timestamp, Data: ev})
}
func (e *Engine) Stats() core.TCPReassemblyStats {
	closed := atomic.LoadUint64(&e.st.closed)
	avgMS := float64(0)
	if closed > 0 {
		avgMS = float64(atomic.LoadUint64(&e.st.durationNanos)) / float64(closed) / float64(time.Millisecond)
	}
	return core.TCPReassemblyStats{
		Enabled: e.cfg.Enabled, Running: e.running.Load(),
		ActiveConnections: atomic.LoadInt64(&e.st.active), PeakActiveConnections: atomic.LoadInt64(&e.st.peakActive),
		ConnectionsOpened: atomic.LoadUint64(&e.st.opened), ConnectionsClosed: closed,
		BufferedBytes: atomic.LoadInt64(&e.st.buffered), BufferedBytesHighWater: atomic.LoadInt64(&e.st.bufferedHighWater),
		SegmentsSeen: atomic.LoadUint64(&e.st.segments), BytesSeen: atomic.LoadUint64(&e.st.bytes), ChunksEmitted: atomic.LoadUint64(&e.st.chunks), BytesEmitted: atomic.LoadUint64(&e.st.emitted),
		OutOfOrderSegments: atomic.LoadUint64(&e.st.outOfOrder), RetransmittedBytes: atomic.LoadUint64(&e.st.retransmitted), OverlapSegments: atomic.LoadUint64(&e.st.overlaps), OverlapConflicts: atomic.LoadUint64(&e.st.overlapConflicts),
		GapRecoveries: atomic.LoadUint64(&e.st.gapRecoveries), EvictedConnections: atomic.LoadUint64(&e.st.evicted), DroppedSegments: atomic.LoadUint64(&e.st.dropped), DuplicateSegments: atomic.LoadUint64(&e.st.duplicates),
		TimedOutConnections: atomic.LoadUint64(&e.st.timedOut), ResetConnections: atomic.LoadUint64(&e.st.resets), AverageDurationMS: avgMS, MaxConnectionsPerIPDrops: atomic.LoadUint64(&e.st.perIPDrops),
		MidstreamConnections: atomic.LoadUint64(&e.st.midstream), AsymmetricConnections: atomic.LoadUint64(&e.st.asymmetric), LowConfidenceChunks: atomic.LoadUint64(&e.st.lowConfidence),
	}
}
