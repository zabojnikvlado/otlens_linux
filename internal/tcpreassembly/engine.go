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
}

type segment struct {
	seq  uint32
	data []byte
	ts   time.Time
}
type direction struct {
	initialized bool
	next        uint32
	pending     map[uint32]segment
	buffered    int
	midstream   bool
	gapped      bool
	gapSince    time.Time
	protocol    string
}
type connection struct {
	id                 string
	aIP, bIP           string
	aPort, bPort       uint16
	a2b, b2a           direction
	lastSeen, closedAt time.Time
}
type shard struct {
	mu       sync.Mutex
	conns    map[string]*connection
	buffered int
}

type stats struct {
	active                                                                                                                   int64
	buffered                                                                                                                 int64
	segments, bytes, chunks, emitted, outOfOrder, retransmitted, overlaps, overlapConflicts, gapRecoveries, evicted, dropped uint64
}

type Engine struct {
	bus    *core.EventBus
	cfg    Config
	shards []shard
	pool   sync.Pool
	st     stats
	stop   chan struct{}
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
	e := &Engine{bus: bus, cfg: cfg, shards: make([]shard, cfg.ShardCount), stop: make(chan struct{})}
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

func (e *Engine) Push(p core.Packet) {
	if p.L4Protocol != "TCP" {
		return
	}
	if len(p.AppPayload) == 0 && !hasFlag(p.TCPFlags, "SYN") && !hasFlag(p.TCPFlags, "FIN") && !hasFlag(p.TCPFlags, "RST") {
		return
	}
	atomic.AddUint64(&e.st.segments, 1)
	atomic.AddUint64(&e.st.bytes, uint64(len(p.AppPayload)))
	id, forward := canonical(p)
	s := e.shardFor(id)
	s.mu.Lock()
	c := s.conns[id]
	if c == nil {
		if atomic.LoadInt64(&e.st.active) >= int64(e.cfg.MaxConnections) {
			e.evictOldestLocked(s, "connection_limit")
		}
		c = &connection{id: id, lastSeen: p.Timestamp}
		if forward {
			c.aIP, c.aPort, c.bIP, c.bPort = p.SrcIP, p.SrcPort, p.DstIP, p.DstPort
		} else {
			c.aIP, c.aPort, c.bIP, c.bPort = p.DstIP, p.DstPort, p.SrcIP, p.SrcPort
		}
		c.a2b.pending = map[uint32]segment{}
		c.b2a.pending = map[uint32]segment{}
		s.conns[id] = c
		atomic.AddInt64(&e.st.active, 1)
		e.publishLifecycle(c, "opened", "")
	}
	c.lastSeen = p.Timestamp
	d := &c.a2b
	if !forward {
		d = &c.b2a
	}
	seq := p.TCPSeq
	if hasFlag(p.TCPFlags, "SYN") {
		seq++
	}
	chunks := e.acceptLocked(s, c, d, seq, p.AppPayload, p.Timestamp, forward)
	if hasFlag(p.TCPFlags, "FIN") || hasFlag(p.TCPFlags, "RST") {
		c.closedAt = p.Timestamp
		e.publishLifecycle(c, "closing", strings.ToLower(p.TCPFlags))
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
		d.midstream = true
	}
	overlap := false
	if seqLess(seq, d.next) {
		skip := uint32(d.next - seq)
		atomic.AddUint64(&e.st.retransmitted, uint64(minU32(skip, uint32(len(data)))))
		if skip >= uint32(len(data)) {
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
			e.publishLifecycle(c, "truncated", "reassembly_limit")
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
				atomic.AddInt64(&e.st.buffered, int64(len(cp)))
			}
			return nil
		}
		cp := e.copyBytes(data)
		d.pending[seq] = segment{seq: seq, data: cp, ts: ts}
		d.buffered += len(cp)
		s.buffered += len(cp)
		atomic.AddInt64(&e.st.buffered, int64(len(cp)))
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
		if proto == "" || proto == "unknown" {
			proto = streamproto.Detect(b)
			if proto != "unknown" {
				d.protocol = proto
			}
		}
		cp := append([]byte(nil), b...)
		out = append(out, core.TCPStreamChunk{ConnectionID: c.id, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Timestamp: t, Data: cp, Midstream: d.midstream, Gapped: d.gapped, GapBefore: gap, Overlap: overlap, Protocol: proto})
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
			publish = append(publish, e.recoverDirectionLocked(s, c, &c.a2b, now, true)...)
			publish = append(publish, e.recoverDirectionLocked(s, c, &c.b2a, now, false)...)
			timeout := e.cfg.IdleTimeout
			reason := "idle_timeout"
			if !c.closedAt.IsZero() {
				timeout = e.cfg.ClosedTimeout
				reason = "closed"
				if now.Sub(c.closedAt) < timeout {
					continue
				}
			} else if now.Sub(c.lastSeen) < timeout {
				continue
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
	e.publishLifecycle(c, "gapped", "gap_recovery")
	sg := d.pending[first]
	delete(d.pending, first)
	d.buffered -= len(sg.data)
	s.buffered -= len(sg.data)
	atomic.AddInt64(&e.st.buffered, -int64(len(sg.data)))
	out := e.emitContiguousLocked(s, c, d, sg.data, sg.ts, forward, gap, false)
	e.release(sg.data)
	return out
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
	atomic.AddInt64(&e.st.active, -1)
	e.publishLifecycle(c, "closed", reason)
}
func (e *Engine) publishLifecycle(c *connection, typ, reason string) {
	proto := c.a2b.protocol
	if proto == "" {
		proto = c.b2a.protocol
	}
	ev := core.TCPStreamEvent{ConnectionID: c.id, Type: typ, Reason: reason, Timestamp: c.lastSeen, Buffered: c.a2b.buffered + c.b2a.buffered, Protocol: proto}
	e.bus.Publish(core.Event{Type: core.EventTCPStreamLifecycle, Timestamp: ev.Timestamp, Data: ev})
}
func (e *Engine) Stats() core.TCPReassemblyStats {
	return core.TCPReassemblyStats{ActiveConnections: atomic.LoadInt64(&e.st.active), BufferedBytes: atomic.LoadInt64(&e.st.buffered), SegmentsSeen: atomic.LoadUint64(&e.st.segments), BytesSeen: atomic.LoadUint64(&e.st.bytes), ChunksEmitted: atomic.LoadUint64(&e.st.chunks), BytesEmitted: atomic.LoadUint64(&e.st.emitted), OutOfOrderSegments: atomic.LoadUint64(&e.st.outOfOrder), RetransmittedBytes: atomic.LoadUint64(&e.st.retransmitted), OverlapSegments: atomic.LoadUint64(&e.st.overlaps), OverlapConflicts: atomic.LoadUint64(&e.st.overlapConflicts), GapRecoveries: atomic.LoadUint64(&e.st.gapRecoveries), EvictedConnections: atomic.LoadUint64(&e.st.evicted), DroppedSegments: atomic.LoadUint64(&e.st.dropped)}
}
