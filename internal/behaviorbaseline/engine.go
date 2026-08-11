package behaviorbaseline

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/protocolobs"
)

const shardCount = 64
const maxAssetDimensions = 256

type Config struct {
	Enabled          bool
	SensorID         string
	LearningDuration time.Duration
	BucketDuration   time.Duration
	MaxProfiles      int
	MaxAssetProfiles int
}

type sample struct {
	key       Key
	srcAsset  string
	dstAsset  string
	at        time.Time
	bytes     uint64
	rttMillis float64
	operation string
	packet    bool
}

type shard struct {
	mu       sync.RWMutex
	profiles map[Key]*Profile
}

type assetShard struct {
	mu       sync.RWMutex
	profiles map[AssetKey]*AssetBehaviorProfile
}

type Engine struct {
	config       Config
	bus          *core.EventBus
	shards       [shardCount]shard
	assetShards  [shardCount]assetShard
	identityMu   sync.RWMutex
	identityByIP map[string]string

	startMu         sync.RWMutex
	learningStarted time.Time
	stop            chan struct{}
	stopOnce        sync.Once
	wg              sync.WaitGroup

	profiles      atomic.Uint64
	assetProfiles atomic.Uint64
	observed      atomic.Uint64
	dropped       atomic.Uint64
	evicted       atomic.Uint64
}

func New(bus *core.EventBus, config Config) *Engine {
	if config.LearningDuration <= 0 {
		config.LearningDuration = time.Hour
	}
	if config.BucketDuration <= 0 {
		config.BucketDuration = time.Hour
	}
	if config.BucketDuration > 7*24*time.Hour {
		config.BucketDuration = 7 * 24 * time.Hour
	}
	if config.MaxProfiles <= 0 {
		config.MaxProfiles = 100_000
	}
	if config.MaxAssetProfiles <= 0 {
		config.MaxAssetProfiles = 100_000
	}
	e := &Engine{bus: bus, config: config, stop: make(chan struct{}), identityByIP: make(map[string]string)}
	for i := range e.shards {
		e.shards[i].profiles = make(map[Key]*Profile)
		e.assetShards[i].profiles = make(map[AssetKey]*AssetBehaviorProfile)
	}
	return e
}

func (e *Engine) Start() {
	if !e.config.Enabled || e.bus == nil {
		return
	}
	packets := e.bus.Subscribe(core.EventPacketParsed)
	applications := e.bus.Subscribe(core.EventProtocolObservation)
	e.wg.Add(2)
	go e.consumePackets(packets)
	go e.consumeApplications(applications)
}

func (e *Engine) Stop() {
	e.stopOnce.Do(func() { close(e.stop) })
	e.wg.Wait()
}

func (e *Engine) consumePackets(events <-chan core.Event) {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		case event := <-events:
			packet, ok := event.Data.(core.Packet)
			if !ok || packet.SrcIP == "" || packet.DstIP == "" {
				continue
			}
			at := packet.Timestamp
			if at.IsZero() {
				at = event.Timestamp
			}
			srcAsset := e.rememberIdentity(packet.SrcIP, packet.SrcMAC)
			dstAsset := e.rememberIdentity(packet.DstIP, packet.DstMAC)
			e.observe(sample{key: e.key(at, ScopeNetwork, packet.SrcIP, packet.DstIP, packet.L4Protocol, packet.L4Protocol, packet.SrcPort, packet.DstPort), srcAsset: srcAsset, dstAsset: dstAsset, at: at, bytes: uint64(max(packet.Length, 0)), packet: true})
		}
	}
}

func (e *Engine) consumeApplications(events <-chan core.Event) {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		case event := <-events:
			observation, ok := event.Data.(protocolobs.Observation)
			if !ok || observation.SrcIP == "" || observation.DstIP == "" {
				continue
			}
			at := observation.Timestamp
			if at.IsZero() {
				at = event.Timestamp
			}
			sensor := observation.SensorID
			if sensor == "" {
				sensor = e.config.SensorID
			}
			key := e.key(at, ScopeApplication, observation.SrcIP, observation.DstIP, observation.Transport, observation.Protocol, observation.SrcPort, observation.DstPort)
			key.SensorID = sensor
			e.observe(sample{key: key, srcAsset: e.resolveIdentity(sensor, observation.SrcIP), dstAsset: e.resolveIdentity(sensor, observation.DstIP), at: at, rttMillis: observation.RTTMillis, operation: observation.Operation})
		}
	}
}

func (e *Engine) key(at time.Time, scope Scope, srcIP, dstIP, transport, protocol string, srcPort, dstPort uint16) Key {
	servicePort := dstPort
	if srcPort < dstPort {
		servicePort = srcPort
	}
	return Key{SensorID: e.config.SensorID, Scope: scope, SrcIP: srcIP, DstIP: dstIP, Transport: strings.ToLower(transport), Protocol: strings.ToLower(protocol), ServicePort: servicePort, TimeBucket: e.timeBucket(at)}
}

func (e *Engine) NetworkKey(packet core.Packet) Key {
	return e.key(packet.Timestamp, ScopeNetwork, packet.SrcIP, packet.DstIP, packet.L4Protocol, packet.L4Protocol, packet.SrcPort, packet.DstPort)
}

func (e *Engine) ApplicationKey(observation protocolobs.Observation) Key {
	key := e.key(observation.Timestamp, ScopeApplication, observation.SrcIP, observation.DstIP, observation.Transport, observation.Protocol, observation.SrcPort, observation.DstPort)
	if observation.SensorID != "" {
		key.SensorID = observation.SensorID
	}
	return key
}

func (e *Engine) TimeBucket(at time.Time) uint16 { return e.timeBucket(at) }

func (e *Engine) timeBucket(at time.Time) uint16 {
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	weekStart := at.AddDate(0, 0, -int(at.Weekday())).Truncate(24 * time.Hour)
	return uint16(at.Sub(weekStart) / e.config.BucketDuration)
}

func (e *Engine) observe(value sample) {
	if value.at.IsZero() {
		value.at = time.Now().UTC()
	}
	e.ensureStarted(value.at)
	e.observed.Add(1)
	if mode, _ := e.mode(value.at); mode == ModeMonitoring {
		// Monitoring observations are intentionally not folded back into the
		// trusted baseline. Future NBA logic evaluates them against Snapshot();
		// explicit analyst approval/decay can later provide controlled updates.
		e.dropped.Add(1)
		return
	}
	index := hashKey(value.key) % shardCount
	shard := &e.shards[index]
	shard.mu.Lock()
	profile := shard.profiles[value.key]
	if profile == nil {
		capacity := (e.config.MaxProfiles + shardCount - 1) / shardCount
		if len(shard.profiles) >= capacity {
			var oldestKey Key
			var oldest time.Time
			for key, candidate := range shard.profiles {
				if oldest.IsZero() || candidate.LastSeen.Before(oldest) {
					oldestKey, oldest = key, candidate.LastSeen
				}
			}
			delete(shard.profiles, oldestKey)
			e.evicted.Add(1)
			e.profiles.Add(^uint64(0))
		}
		profile = &Profile{Key: value.key, FirstSeen: value.at, Operations: make(map[string]uint64)}
		shard.profiles[value.key] = profile
		e.profiles.Add(1)
	}
	if !profile.LastSeen.IsZero() && value.at.After(profile.LastSeen) {
		profile.InterArrival.Add(float64(value.at.Sub(profile.LastSeen)) / float64(time.Millisecond))
	}
	profile.LastSeen = value.at
	if value.packet {
		profile.Packets++
		profile.Bytes += value.bytes
		profile.PacketBytes.Add(float64(value.bytes))
	}
	if value.rttMillis > 0 {
		profile.RTTMillis.Add(value.rttMillis)
	}
	if value.operation != "" {
		profile.Operations[value.operation]++
	}
	shard.mu.Unlock()
	e.observeAssets(value)
}

func (e *Engine) rememberIdentity(ip, mac string) string {
	identity := "ip:" + ip
	if value := strings.ToLower(strings.TrimSpace(mac)); value != "" {
		identity = "mac:" + value
	}
	if ip != "" {
		e.identityMu.Lock()
		e.identityByIP[e.config.SensorID+"|"+ip] = identity
		e.identityMu.Unlock()
	}
	return identity
}

func (e *Engine) resolveIdentity(sensor, ip string) string {
	e.identityMu.RLock()
	identity := e.identityByIP[sensor+"|"+ip]
	e.identityMu.RUnlock()
	if identity == "" {
		return "ip:" + ip
	}
	return identity
}

func (e *Engine) observeAssets(value sample) {
	if value.srcAsset != "" {
		e.observeAsset(value, value.srcAsset, value.dstAsset, value.key.SrcIP, value.key.DstIP, false)
	}
	if value.dstAsset != "" && value.dstAsset != value.srcAsset {
		e.observeAsset(value, value.dstAsset, value.srcAsset, value.key.DstIP, value.key.SrcIP, true)
	}
}

func (e *Engine) observeAsset(value sample, assetID, peerID, assetIP, peerIP string, inbound bool) {
	key := AssetKey{SensorID: value.key.SensorID, AssetID: assetID, TimeBucket: value.key.TimeBucket}
	index := hashAssetKey(key) % shardCount
	shard := &e.assetShards[index]
	shard.mu.Lock()
	profile := shard.profiles[key]
	if profile == nil {
		capacity := (e.config.MaxAssetProfiles + shardCount - 1) / shardCount
		if len(shard.profiles) >= capacity {
			var oldestKey AssetKey
			var oldest time.Time
			for candidateKey, candidate := range shard.profiles {
				if oldest.IsZero() || candidate.LastSeen.Before(oldest) {
					oldestKey, oldest = candidateKey, candidate.LastSeen
				}
			}
			delete(shard.profiles, oldestKey)
			e.evicted.Add(1)
			e.assetProfiles.Add(^uint64(0))
		}
		profile = &AssetBehaviorProfile{
			Key: key, FirstSeen: value.at, Peers: make(map[string]PeerStats),
			Protocols: make(map[string]DirectionTotals), Ports: make(map[uint16]DirectionTotals),
			Operations: make(map[string]uint64), IPs: make(map[string]uint64),
		}
		shard.profiles[key] = profile
		e.assetProfiles.Add(1)
	}
	if !profile.LastSeen.IsZero() && value.at.After(profile.LastSeen) {
		profile.InterArrival.Add(float64(value.at.Sub(profile.LastSeen)) / float64(time.Millisecond))
	}
	profile.LastSeen = value.at
	if assetIP != "" && (len(profile.IPs) < maxAssetDimensions || profile.IPs[assetIP] > 0) {
		profile.IPs[assetIP]++
	}
	delta := DirectionTotals{Events: 1}
	if value.packet {
		delta.Packets, delta.Bytes = 1, value.bytes
		profile.PacketBytes.Add(float64(value.bytes))
	}
	if inbound {
		addDirection(&profile.Inbound, delta)
	} else {
		addDirection(&profile.Outbound, delta)
	}
	if peerID == "" {
		peerID = "ip:" + peerIP
	}
	_, peerExists := profile.Peers[peerID]
	if len(profile.Peers) < maxAssetDimensions || peerExists {
		peer := profile.Peers[peerID]
		peer.LastSeen = value.at
		if inbound {
			addDirection(&peer.Inbound, delta)
		} else {
			addDirection(&peer.Outbound, delta)
		}
		profile.Peers[peerID] = peer
	}
	if value.key.Protocol != "" && (len(profile.Protocols) < maxAssetDimensions || profile.Protocols[value.key.Protocol].Events > 0) {
		total := profile.Protocols[value.key.Protocol]
		addDirection(&total, delta)
		profile.Protocols[value.key.Protocol] = total
	}
	if value.key.ServicePort > 0 && (len(profile.Ports) < maxAssetDimensions || profile.Ports[value.key.ServicePort].Events > 0) {
		total := profile.Ports[value.key.ServicePort]
		addDirection(&total, delta)
		profile.Ports[value.key.ServicePort] = total
	}
	if value.rttMillis > 0 {
		profile.RTTMillis.Add(value.rttMillis)
	}
	if value.operation != "" && (len(profile.Operations) < maxAssetDimensions || profile.Operations[value.operation] > 0) {
		profile.Operations[value.operation]++
	}
	shard.mu.Unlock()
}

func addDirection(target *DirectionTotals, delta DirectionTotals) {
	target.Packets += delta.Packets
	target.Bytes += delta.Bytes
	target.Events += delta.Events
}

func (e *Engine) ensureStarted(at time.Time) {
	e.startMu.RLock()
	started := !e.learningStarted.IsZero()
	e.startMu.RUnlock()
	if started {
		return
	}
	e.startMu.Lock()
	if e.learningStarted.IsZero() {
		e.learningStarted = at
	}
	e.startMu.Unlock()
}

func (e *Engine) mode(now time.Time) (Mode, time.Time) {
	e.startMu.RLock()
	started := e.learningStarted
	e.startMu.RUnlock()
	if started.IsZero() || now.Before(started.Add(e.config.LearningDuration)) {
		return ModeLearning, started
	}
	return ModeMonitoring, started
}

func (e *Engine) Status(now time.Time) Status {
	mode, started := e.mode(now)
	return Status{Enabled: e.config.Enabled, Mode: mode, LearningStarted: started, LearningEndsAt: started.Add(e.config.LearningDuration), Profiles: e.profiles.Load(), AssetProfiles: e.assetProfiles.Load(), Observed: e.observed.Load(), Dropped: e.dropped.Load(), Evicted: e.evicted.Load()}
}

// Reset discards the complete learned behavior model and restarts the
// learning clock on the next observation.
func (e *Engine) Reset() {
	for i := range e.shards {
		e.shards[i].mu.Lock()
		e.shards[i].profiles = make(map[Key]*Profile)
		e.shards[i].mu.Unlock()
		e.assetShards[i].mu.Lock()
		e.assetShards[i].profiles = make(map[AssetKey]*AssetBehaviorProfile)
		e.assetShards[i].mu.Unlock()
	}
	e.identityMu.Lock()
	e.identityByIP = make(map[string]string)
	e.identityMu.Unlock()
	e.startMu.Lock()
	e.learningStarted = time.Time{}
	e.startMu.Unlock()
	e.profiles.Store(0)
	e.assetProfiles.Store(0)
	e.observed.Store(0)
	e.dropped.Store(0)
	e.evicted.Store(0)
}

func (e *Engine) Snapshot(now time.Time) Snapshot {
	mode, started := e.mode(now)
	result := Snapshot{Version: 2, Mode: mode, LearningStarted: started, LearningEndsAt: started.Add(e.config.LearningDuration), CapturedAt: now, Profiles: make([]Profile, 0, e.profiles.Load()), Observed: e.observed.Load(), Dropped: e.dropped.Load(), Evicted: e.evicted.Load()}
	for i := range e.shards {
		e.shards[i].mu.RLock()
		for _, profile := range e.shards[i].profiles {
			copyProfile := *profile
			copyProfile.Operations = make(map[string]uint64, len(profile.Operations))
			for operation, count := range profile.Operations {
				copyProfile.Operations[operation] = count
			}
			result.Profiles = append(result.Profiles, copyProfile)
		}
		e.shards[i].mu.RUnlock()
	}
	result.AssetProfiles = e.AssetProfiles()
	return result
}

// AssetProfiles returns detached copies safe for NBA evaluation and APIs.
func (e *Engine) AssetProfiles() []AssetBehaviorProfile {
	result := make([]AssetBehaviorProfile, 0, e.assetProfiles.Load())
	for i := range e.assetShards {
		e.assetShards[i].mu.RLock()
		for _, profile := range e.assetShards[i].profiles {
			result = append(result, cloneAssetProfile(profile))
		}
		e.assetShards[i].mu.RUnlock()
	}
	return result
}

// AssetProfile retrieves one exact asset/time-bucket profile without exposing
// mutable engine state.
func (e *Engine) AssetProfile(key AssetKey) (AssetBehaviorProfile, bool) {
	index := hashAssetKey(key) % shardCount
	e.assetShards[index].mu.RLock()
	profile := e.assetShards[index].profiles[key]
	if profile == nil {
		e.assetShards[index].mu.RUnlock()
		return AssetBehaviorProfile{}, false
	}
	result := cloneAssetProfile(profile)
	e.assetShards[index].mu.RUnlock()
	return result, true
}

func (e *Engine) Restore(snapshot Snapshot) error {
	if snapshot.Version > 2 {
		return fmt.Errorf("unsupported behavior baseline snapshot version %d", snapshot.Version)
	}
	for _, profile := range snapshot.Profiles {
		index := hashKey(profile.Key) % shardCount
		copyProfile := profile
		if copyProfile.Operations == nil {
			copyProfile.Operations = make(map[string]uint64)
		}
		e.shards[index].profiles[profile.Key] = &copyProfile
	}
	for _, profile := range snapshot.AssetProfiles {
		index := hashAssetKey(profile.Key) % shardCount
		copyProfile := cloneAssetProfile(&profile)
		e.assetShards[index].profiles[profile.Key] = &copyProfile
		for ip := range profile.IPs {
			e.identityByIP[profile.Key.SensorID+"|"+ip] = profile.Key.AssetID
		}
	}
	e.profiles.Store(uint64(len(snapshot.Profiles)))
	e.assetProfiles.Store(uint64(len(snapshot.AssetProfiles)))
	e.observed.Store(snapshot.Observed)
	e.dropped.Store(snapshot.Dropped)
	e.evicted.Store(snapshot.Evicted)
	e.learningStarted = snapshot.LearningStarted
	return nil
}

func cloneAssetProfile(profile *AssetBehaviorProfile) AssetBehaviorProfile {
	copyProfile := *profile
	copyProfile.Peers = make(map[string]PeerStats, len(profile.Peers))
	for key, value := range profile.Peers {
		copyProfile.Peers[key] = value
	}
	copyProfile.Protocols = make(map[string]DirectionTotals, len(profile.Protocols))
	for key, value := range profile.Protocols {
		copyProfile.Protocols[key] = value
	}
	copyProfile.Ports = make(map[uint16]DirectionTotals, len(profile.Ports))
	for key, value := range profile.Ports {
		copyProfile.Ports[key] = value
	}
	copyProfile.Operations = make(map[string]uint64, len(profile.Operations))
	for key, value := range profile.Operations {
		copyProfile.Operations[key] = value
	}
	copyProfile.IPs = make(map[string]uint64, len(profile.IPs))
	for key, value := range profile.IPs {
		copyProfile.IPs[key] = value
	}
	return copyProfile
}

func hashKey(key Key) int {
	hash := uint32(2166136261)
	addString := func(value string) {
		for i := 0; i < len(value); i++ {
			hash ^= uint32(value[i])
			hash *= 16777619
		}
		hash ^= 0xff
		hash *= 16777619
	}
	addString(key.SensorID)
	addString(string(key.Scope))
	addString(key.SrcIP)
	addString(key.DstIP)
	addString(key.Transport)
	addString(key.Protocol)
	hash ^= uint32(key.ServicePort)
	hash *= 16777619
	hash ^= uint32(key.TimeBucket)
	hash *= 16777619
	return int(hash & 0x7fffffff)
}

func hashAssetKey(key AssetKey) int {
	hash := uint32(2166136261)
	for _, value := range []string{key.SensorID, key.AssetID} {
		for i := 0; i < len(value); i++ {
			hash ^= uint32(value[i])
			hash *= 16777619
		}
		hash ^= 0xff
		hash *= 16777619
	}
	hash ^= uint32(key.TimeBucket)
	hash *= 16777619
	return int(hash & 0x7fffffff)
}
