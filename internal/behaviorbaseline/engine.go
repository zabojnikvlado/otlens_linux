package behaviorbaseline

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/netutil"
	"github.com/zabojnikvlado/otlens_linux/internal/protocolobs"
)

const shardCount = 64
const maxAssetDimensions = 256
const maxCandidateStatus = 50
const maxPatternHistory = 10000
const publicInternetReviewReason = "public internet communication requires explicit approval"

type Config struct {
	Enabled          bool
	SensorID         string
	LearningDuration time.Duration
	BucketDuration   time.Duration
	MaxProfiles      int
	MaxAssetProfiles int

	// Readiness turns LearningDuration into a minimum rather than a blind
	// deadline. These defaults deliberately work without adding required
	// config keys; deployments can override them later.
	MinAssetSamples       int
	MinAssetAge           time.Duration
	ReadinessThreshold    float64
	MaxLearningMultiplier float64
	CandidateMinSamples   int
	CandidateMinDays      int
	MinStatSamples        int
	MaintenanceWindows    []string
}

type maintenanceWindow struct {
	days        map[time.Weekday]bool
	startMinute int
	endMinute   int
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

type candidateState struct {
	Candidate
	profile  Profile
	srcAsset string
	dstAsset string
	days     map[string]struct{}
}

type Engine struct {
	config      Config
	bus         *core.EventBus
	shards      [shardCount]shard
	assetShards [shardCount]assetShard

	identityMu   sync.RWMutex
	identityByIP map[string]string

	startMu          sync.RWMutex
	learningStarted  time.Time
	learningComplete bool

	candidateMu sync.RWMutex
	candidates  map[string]*candidateState

	exclusionMu sync.RWMutex
	exclusions  map[string]time.Time

	patternMu      sync.Mutex
	patternCreated []time.Time

	maintenance []maintenanceWindow

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	profiles      atomic.Uint64
	assetProfiles atomic.Uint64
	observed      atomic.Uint64
	dropped       atomic.Uint64
	excluded      atomic.Uint64
	evicted       atomic.Uint64
	revision      atomic.Uint64
}

func New(bus *core.EventBus, config Config) *Engine {
	if config.LearningDuration <= 0 {
		config.LearningDuration = time.Hour
	}
	if config.BucketDuration <= 0 {
		config.BucketDuration = time.Hour
	}
	if config.BucketDuration > 24*time.Hour {
		config.BucketDuration = 24 * time.Hour
	}
	if config.MaxProfiles <= 0 {
		config.MaxProfiles = 100_000
	}
	if config.MaxAssetProfiles <= 0 {
		config.MaxAssetProfiles = 100_000
	}
	if config.MinAssetSamples <= 0 {
		config.MinAssetSamples = 50
	}
	if config.MinAssetAge <= 0 {
		config.MinAssetAge = config.LearningDuration / 4
		// Short learning windows are useful in tests/development. Do not make
		// their per-asset maturity age longer than the whole learning phase.
		if config.LearningDuration < 5*time.Minute {
			if config.MinAssetAge < time.Millisecond {
				config.MinAssetAge = time.Millisecond
			}
		} else if config.MinAssetAge < 5*time.Minute {
			config.MinAssetAge = 5 * time.Minute
		}
		if config.MinAssetAge > time.Hour {
			config.MinAssetAge = time.Hour
		}
	}
	if config.LearningDuration < 5*time.Minute && config.MinAssetSamples == 50 {
		config.MinAssetSamples = 5
	}
	if config.ReadinessThreshold <= 0 || config.ReadinessThreshold > 1 {
		config.ReadinessThreshold = .85
	}
	if config.MaxLearningMultiplier < 1.25 {
		config.MaxLearningMultiplier = 2
	}
	if config.CandidateMinSamples <= 0 {
		config.CandidateMinSamples = 20
	}
	if config.CandidateMinDays <= 0 {
		config.CandidateMinDays = 3
	}
	if config.MinStatSamples <= 0 {
		config.MinStatSamples = 30
	}

	e := &Engine{
		bus:          bus,
		config:       config,
		stop:         make(chan struct{}),
		identityByIP: make(map[string]string),
		candidates:   make(map[string]*candidateState),
		exclusions:   make(map[string]time.Time),
		maintenance:  parseMaintenanceWindows(config.MaintenanceWindows),
	}
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
	exclusions := e.bus.Subscribe(core.EventLearningExclusion)
	e.wg.Add(3)
	go e.consumePackets(packets)
	go e.consumeApplications(applications)
	go e.consumeExclusions(exclusions)
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
		case event, ok := <-events:
			if !ok {
				return
			}
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
			key := e.networkKey(packet)
			if at.IsZero() {
				at = time.Now().UTC()
				key = e.keyWithService(at, ScopeNetwork, packet.SrcIP, packet.DstIP, packet.L4Protocol, packet.L4Protocol, key.ServicePort)
			}
			e.observe(sample{key: key, srcAsset: srcAsset, dstAsset: dstAsset, at: at, bytes: uint64(max(packet.Length, 0)), packet: true})
		}
	}
}

func (e *Engine) consumeApplications(events <-chan core.Event) {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		case event, ok := <-events:
			if !ok {
				return
			}
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
			key := e.applicationKey(observation)
			key.SensorID = sensor
			e.observe(sample{key: key, srcAsset: e.resolveIdentity(sensor, observation.SrcIP), dstAsset: e.resolveIdentity(sensor, observation.DstIP), at: at, rttMillis: observation.RTTMillis, operation: observation.Operation})
		}
	}
}

func (e *Engine) consumeExclusions(events <-chan core.Event) {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			exclusion, ok := event.Data.(core.LearningExclusion)
			if !ok {
				continue
			}
			e.ApplyLearningExclusion(exclusion)
		}
	}
}

func servicePort(srcPort, dstPort uint16) uint16 {
	if srcPort == 0 {
		return dstPort
	}
	if dstPort == 0 {
		return srcPort
	}
	if srcPort < dstPort {
		return srcPort
	}
	return dstPort
}

func tcpServicePort(packet core.Packet) uint16 {
	flags := strings.ToUpper(packet.TCPFlags)
	if strings.Contains(flags, "SYN") {
		if strings.Contains(flags, "ACK") {
			if packet.SrcPort != 0 {
				return packet.SrcPort
			}
		} else if packet.DstPort != 0 {
			return packet.DstPort
		}
	}
	return servicePort(packet.SrcPort, packet.DstPort)
}

func appServicePort(observation protocolobs.Observation) uint16 {
	direction := strings.ToLower(strings.TrimSpace(observation.Direction))
	switch {
	case strings.Contains(direction, "response"), strings.Contains(direction, "server"):
		if observation.SrcPort != 0 {
			return observation.SrcPort
		}
	case strings.Contains(direction, "request"), strings.Contains(direction, "client"):
		if observation.DstPort != 0 {
			return observation.DstPort
		}
	}
	return servicePort(observation.SrcPort, observation.DstPort)
}

func (e *Engine) networkKey(packet core.Packet) Key {
	port := servicePort(packet.SrcPort, packet.DstPort)
	if strings.EqualFold(packet.L4Protocol, "tcp") {
		port = tcpServicePort(packet)
	}
	return e.keyWithService(packet.Timestamp, ScopeNetwork, packet.SrcIP, packet.DstIP, packet.L4Protocol, packet.L4Protocol, port)
}

func (e *Engine) applicationKey(observation protocolobs.Observation) Key {
	return e.keyWithService(observation.Timestamp, ScopeApplication, observation.SrcIP, observation.DstIP, observation.Transport, observation.Protocol, appServicePort(observation))
}

func (e *Engine) key(at time.Time, scope Scope, srcIP, dstIP, transport, protocol string, srcPort, dstPort uint16) Key {
	return e.keyWithService(at, scope, srcIP, dstIP, transport, protocol, servicePort(srcPort, dstPort))
}

func (e *Engine) keyWithService(at time.Time, scope Scope, srcIP, dstIP, transport, protocol string, svc uint16) Key {
	bucket, dayClass, shift, context := e.timeContext(at)
	return Key{SensorID: e.config.SensorID, Scope: scope, SrcIP: srcIP, DstIP: dstIP, Transport: strings.ToLower(transport), Protocol: strings.ToLower(protocol), ServicePort: svc, TimeBucket: bucket, DayClass: dayClass, Shift: shift, Context: context}
}

func (e *Engine) NetworkKey(packet core.Packet) Key { return e.networkKey(packet) }

func (e *Engine) ApplicationKey(observation protocolobs.Observation) Key {
	key := e.applicationKey(observation)
	if observation.SensorID != "" {
		key.SensorID = observation.SensorID
	}
	return key
}

func (e *Engine) TimeBucket(at time.Time) uint16 {
	bucket, _, _, _ := e.timeContext(at)
	return bucket
}

func (e *Engine) timeContext(at time.Time) (uint16, string, string, string) {
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	minutes := at.Hour()*60 + at.Minute()
	bucketMinutes := int(e.config.BucketDuration / time.Minute)
	if bucketMinutes <= 0 {
		bucketMinutes = 60
	}
	bucket := uint16(minutes / bucketMinutes)
	dayClass := "weekday"
	if at.Weekday() == time.Saturday || at.Weekday() == time.Sunday {
		dayClass = "weekend"
	}
	shift := "night"
	switch {
	case at.Hour() >= 6 && at.Hour() < 14:
		shift = "day"
	case at.Hour() >= 14 && at.Hour() < 22:
		shift = "evening"
	}
	context := "production"
	if e.isMaintenance(at) {
		context = "maintenance"
	}
	return bucket, dayClass, shift, context
}

func (e *Engine) observe(value sample) {
	if value.at.IsZero() {
		value.at = time.Now().UTC()
	}
	e.ensureStarted(value.at)
	e.observed.Add(1)

	mode, _ := e.mode(value.at)
	eligible, reason := e.trustedLearningEligible(value)
	reviewOnly := reason == publicInternetReviewReason
	if mode == ModeLearning {
		if e.isExcluded(value.key, value.at) {
			e.excluded.Add(1)
			return
		}
		if !eligible {
			// Public Internet relationships are never silently trusted, but they
			// are retained in the shadow baseline so an analyst can explicitly
			// promote a reviewed/allowed relationship after enough evidence.
			if reviewOnly {
				e.observeCandidate(value, true, reason)
				return
			}
			e.excluded.Add(1)
			return
		}
		e.observeTrusted(value)
		return
	}

	if e.hasTrustedKey(value.key) {
		e.dropped.Add(1)
		return
	}
	if reviewOnly {
		eligible = true
	}
	e.observeCandidate(value, eligible, reason)
}

func (e *Engine) trustedLearningEligible(value sample) (bool, string) {
	// Internet destinations are a policy decision, not something learning may
	// silently bless as normal. They remain visible through external_comm and
	// can be explicitly allowed by policy instead.
	if (netutil.IsPublicInternetUnicast(value.key.SrcIP) && isInternalAddress(value.key.DstIP)) || (netutil.IsPublicInternetUnicast(value.key.DstIP) && isInternalAddress(value.key.SrcIP)) {
		return false, publicInternetReviewReason
	}
	// Maintenance is learned under an explicit, separate context. NBA never
	// compares maintenance observations against production behavior, so planned
	// work does not contaminate the production baseline while still remaining
	// explainable/searchable as known maintenance behavior.
	return true, ""
}

func isInternalAddress(ip string) bool {
	// netutil intentionally has the strict public predicate; anything that is
	// not public and parses as an ordinary endpoint is treated as local here.
	return ip != "" && !netutil.IsPublicInternetUnicast(ip)
}

func (e *Engine) hasTrustedKey(key Key) bool {
	index := hashKey(key) % shardCount
	e.shards[index].mu.RLock()
	_, ok := e.shards[index].profiles[key]
	e.shards[index].mu.RUnlock()
	if ok {
		return true
	}
	// Hierarchical time fallback: a flow learned at the same time-of-day on a
	// different day class is still a known flow; NBA may separately flag the
	// unusual day context at a lower weight.
	for i := range e.shards {
		e.shards[i].mu.RLock()
		for candidate := range e.shards[i].profiles {
			if sameFlowBase(candidate, key) && candidate.TimeBucket == key.TimeBucket && candidate.Context == key.Context {
				e.shards[i].mu.RUnlock()
				return true
			}
		}
		e.shards[i].mu.RUnlock()
	}
	return false
}

func sameFlowBase(a, b Key) bool {
	return a.SensorID == b.SensorID && a.Scope == b.Scope && a.SrcIP == b.SrcIP && a.DstIP == b.DstIP && a.Transport == b.Transport && a.Protocol == b.Protocol && a.ServicePort == b.ServicePort
}

func (e *Engine) observeTrusted(value sample) {
	index := hashKey(value.key) % shardCount
	shard := &e.shards[index]
	created := false
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
		created = true
	}
	updateProfile(profile, value)
	shard.mu.Unlock()
	if created {
		e.recordPatternCreated(value.at)
	}
	e.observeAssets(value)
	e.revision.Add(1)
}

func updateProfile(profile *Profile, value sample) {
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
}

func (e *Engine) observeCandidate(value sample, eligible bool, reason string) {
	id := candidateID(value.key)
	day := value.at.UTC().Format("2006-01-02")
	e.candidateMu.Lock()
	candidate := e.candidates[id]
	if candidate == nil {
		if len(e.candidates) >= e.config.MaxProfiles {
			var oldestID string
			var oldest time.Time
			for candidateID, item := range e.candidates {
				if oldest.IsZero() || item.LastSeen.Before(oldest) {
					oldestID, oldest = candidateID, item.LastSeen
				}
			}
			delete(e.candidates, oldestID)
		}
		candidate = &candidateState{
			Candidate: Candidate{ID: id, Key: value.key, FirstSeen: value.at, Eligible: eligible, Reason: reason},
			profile:   Profile{Key: value.key, FirstSeen: value.at, Operations: make(map[string]uint64)},
			srcAsset:  value.srcAsset, dstAsset: value.dstAsset, days: make(map[string]struct{}),
		}
		e.candidates[id] = candidate
	}
	candidate.LastSeen = value.at
	candidate.Observations++
	candidate.days[day] = struct{}{}
	candidate.DistinctDays = len(candidate.days)
	if !eligible {
		candidate.Eligible = false
		if reason != "" {
			candidate.Reason = reason
		}
	}
	updateProfile(&candidate.profile, value)
	e.candidateMu.Unlock()
}

func candidateID(key Key) string {
	return fmt.Sprintf("candidate|%s|%s|%s|%s|%s|%d|%d|%s|%s", key.SensorID, key.Scope, key.SrcIP, key.DstIP, key.Protocol, key.ServicePort, key.TimeBucket, key.DayClass, key.Context)
}

// PromoteCandidate explicitly moves one shadow candidate into the trusted
// baseline. It is intentionally operator-driven: there is no silent automatic
// promotion of post-learning communication.
func (e *Engine) PromoteCandidate(id string) error {
	e.candidateMu.Lock()
	candidate := e.candidates[id]
	if candidate == nil {
		e.candidateMu.Unlock()
		return fmt.Errorf("candidate %q not found", id)
	}
	if !candidate.Eligible {
		reason := candidate.Reason
		e.candidateMu.Unlock()
		return fmt.Errorf("candidate %q is not eligible for promotion: %s", id, reason)
	}
	if candidate.Observations < uint64(e.config.CandidateMinSamples) || candidate.DistinctDays < e.config.CandidateMinDays {
		observations, days := candidate.Observations, candidate.DistinctDays
		e.candidateMu.Unlock()
		return fmt.Errorf("candidate %q needs at least %d observations across %d days before promotion (have %d across %d days)", id, e.config.CandidateMinSamples, e.config.CandidateMinDays, observations, days)
	}
	copyState := *candidate
	delete(e.candidates, id)
	e.candidateMu.Unlock()

	value := sample{key: copyState.Key, srcAsset: copyState.srcAsset, dstAsset: copyState.dstAsset, at: copyState.LastSeen}
	index := hashKey(copyState.Key) % shardCount
	e.shards[index].mu.Lock()
	profile := copyState.profile
	_, existed := e.shards[index].profiles[copyState.Key]
	e.shards[index].profiles[copyState.Key] = &profile
	e.shards[index].mu.Unlock()
	if !existed {
		e.profiles.Add(1)
	}
	// Seed asset-level knowledge conservatively with the observed relationship.
	events := copyState.Observations
	if events == 0 {
		events = 1
	}
	e.observePromotedAsset(value, copyState.srcAsset, copyState.dstAsset, false, events)
	e.observePromotedAsset(value, copyState.dstAsset, copyState.srcAsset, true, events)
	e.revision.Add(1)
	return nil
}

func (e *Engine) observePromotedAsset(value sample, assetID, peerID string, inbound bool, events uint64) {
	if assetID == "" {
		return
	}
	key := AssetKey{SensorID: value.key.SensorID, AssetID: assetID, TimeBucket: value.key.TimeBucket, DayClass: value.key.DayClass, Shift: value.key.Shift, Context: value.key.Context}
	index := hashAssetKey(key) % shardCount
	shard := &e.assetShards[index]
	shard.mu.Lock()
	profile := shard.profiles[key]
	if profile == nil {
		profile = &AssetBehaviorProfile{Key: key, FirstSeen: value.at, LastSeen: value.at, Peers: make(map[string]PeerStats), Protocols: make(map[string]DirectionTotals), Ports: make(map[uint16]DirectionTotals), Operations: make(map[string]uint64), IPs: make(map[string]uint64)}
		shard.profiles[key] = profile
		e.assetProfiles.Add(1)
	}
	total := DirectionTotals{Events: events}
	if inbound {
		addDirection(&profile.Inbound, total)
	} else {
		addDirection(&profile.Outbound, total)
	}
	if peerID != "" {
		peer := profile.Peers[peerID]
		if inbound {
			addDirection(&peer.Inbound, total)
		} else {
			addDirection(&peer.Outbound, total)
		}
		peer.LastSeen = value.at
		profile.Peers[peerID] = peer
	}
	proto := profile.Protocols[value.key.Protocol]
	addDirection(&proto, total)
	profile.Protocols[value.key.Protocol] = proto
	if value.key.ServicePort != 0 {
		port := profile.Ports[value.key.ServicePort]
		addDirection(&port, total)
		profile.Ports[value.key.ServicePort] = port
	}
	shard.mu.Unlock()
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
	key := AssetKey{SensorID: value.key.SensorID, AssetID: assetID, TimeBucket: value.key.TimeBucket, DayClass: value.key.DayClass, Shift: value.key.Shift, Context: value.key.Context}
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
		profile = &AssetBehaviorProfile{Key: key, FirstSeen: value.at, Peers: make(map[string]PeerStats), Protocols: make(map[string]DirectionTotals), Ports: make(map[uint16]DirectionTotals), Operations: make(map[string]uint64), IPs: make(map[string]uint64)}
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
	complete := e.learningComplete
	e.startMu.RUnlock()
	if complete {
		return ModeMonitoring, started
	}
	if started.IsZero() {
		return ModeLearning, started
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	elapsed := now.Sub(started)
	if elapsed < e.config.LearningDuration {
		return ModeLearning, started
	}
	readiness, ready, _ := e.readiness(now)
	_ = readiness
	if ready || elapsed >= time.Duration(float64(e.config.LearningDuration)*e.config.MaxLearningMultiplier) {
		return ModeMonitoring, started
	}
	return ModeLearning, started
}

// CompleteLearning freezes the current trusted behavior baseline and moves the
// engine into monitoring. The normal path is only allowed after the configured
// minimum learning duration. force is an explicit break-glass override for an
// operator who intentionally accepts an immature baseline.
func (e *Engine) CompleteLearning(force bool) (bool, error) {
	if !e.config.Enabled {
		return false, nil
	}
	now := time.Now().UTC()
	mode, _ := e.mode(now)

	e.startMu.Lock()
	defer e.startMu.Unlock()
	if e.learningComplete {
		return false, nil
	}
	if e.learningStarted.IsZero() {
		return false, fmt.Errorf("behavior baseline learning has not started")
	}
	if mode == ModeMonitoring {
		// Persist the derived automatic transition as an explicit frozen state.
		e.learningComplete = true
		e.revision.Add(1)
		return false, nil
	}
	if !force && now.Sub(e.learningStarted) < e.config.LearningDuration {
		return false, fmt.Errorf("minimum behavior learning duration has not elapsed")
	}
	e.learningComplete = true
	e.revision.Add(1)
	return true, nil
}

func (e *Engine) readiness(now time.Time) (float64, bool, string) {
	e.startMu.RLock()
	started := e.learningStarted
	e.startMu.RUnlock()
	if started.IsZero() {
		return 0, false, "waiting for first traffic"
	}
	elapsed := now.Sub(started)
	durationScore := float64(elapsed) / float64(e.config.LearningDuration)
	if durationScore > 1 {
		durationScore = 1
	}
	maturities := e.assetMaturities(now, false)
	mature := 0
	for _, item := range maturities {
		if item.Mature {
			mature++
		}
	}
	maturityRatio := 0.0
	if len(maturities) > 0 {
		maturityRatio = float64(mature) / float64(len(maturities))
	}
	timeCoverage := e.timeCoverage()
	novelty := e.newPatternRate(now)
	stability := 1 - minFloat(1, novelty/.05)
	readiness := .35*durationScore + .35*maturityRatio + .15*timeCoverage + .15*stability
	if readiness > 1 {
		readiness = 1
	}
	ready := elapsed >= e.config.LearningDuration && readiness >= e.config.ReadinessThreshold && maturityRatio >= .75 && novelty <= .05
	reason := "baseline still accumulating coverage"
	switch {
	case elapsed < e.config.LearningDuration:
		reason = "minimum learning duration not reached"
	case maturityRatio < .75:
		reason = "too many assets still have low-sample profiles"
	case novelty > .05:
		reason = "new communication patterns are still arriving too quickly"
	case timeCoverage < .5:
		reason = "time-of-day coverage is still limited"
	case ready:
		reason = "baseline maturity and stability thresholds satisfied"
	}
	return readiness, ready, reason
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func (e *Engine) assetMaturities(now time.Time, includeCandidates bool) []AssetMaturity {
	type aggregate struct {
		first, last time.Time
		samples     uint64
		buckets     map[uint16]struct{}
	}
	byAsset := make(map[string]*aggregate)
	for i := range e.assetShards {
		e.assetShards[i].mu.RLock()
		for _, profile := range e.assetShards[i].profiles {
			if profile.Key.Context == "maintenance" {
				continue
			}
			agg := byAsset[profile.Key.AssetID]
			if agg == nil {
				agg = &aggregate{buckets: make(map[uint16]struct{})}
				byAsset[profile.Key.AssetID] = agg
			}
			if agg.first.IsZero() || profile.FirstSeen.Before(agg.first) {
				agg.first = profile.FirstSeen
			}
			if profile.LastSeen.After(agg.last) {
				agg.last = profile.LastSeen
			}
			agg.samples += profile.Inbound.Events + profile.Outbound.Events
			agg.buckets[profile.Key.TimeBucket] = struct{}{}
		}
		e.assetShards[i].mu.RUnlock()
	}
	out := make([]AssetMaturity, 0, len(byAsset))
	for id, agg := range byAsset {
		ageScore := minFloat(1, float64(now.Sub(agg.first))/float64(e.config.MinAssetAge))
		sampleScore := minFloat(1, float64(agg.samples)/float64(e.config.MinAssetSamples))
		readiness := .45*ageScore + .55*sampleScore
		out = append(out, AssetMaturity{AssetID: id, FirstSeen: agg.first, LastSeen: agg.last, Samples: agg.samples, TimeBuckets: len(agg.buckets), Mature: ageScore >= 1 && sampleScore >= 1, Readiness: readiness})
	}
	if includeCandidates {
		// Candidate-only assets are surfaced for the dashboard but never count
		// toward trusted baseline readiness.
		known := make(map[string]bool, len(out))
		for _, item := range out {
			known[item.AssetID] = true
		}
		e.candidateMu.RLock()
		candidateAssets := make(map[string]*AssetMaturity)
		for _, candidate := range e.candidates {
			for _, id := range []string{candidate.srcAsset, candidate.dstAsset} {
				if id == "" || known[id] {
					continue
				}
				item := candidateAssets[id]
				if item == nil {
					item = &AssetMaturity{AssetID: id, FirstSeen: candidate.FirstSeen, CandidateOnly: true}
					candidateAssets[id] = item
				}
				if candidate.FirstSeen.Before(item.FirstSeen) {
					item.FirstSeen = candidate.FirstSeen
				}
				if candidate.LastSeen.After(item.LastSeen) {
					item.LastSeen = candidate.LastSeen
				}
				item.Samples += candidate.Observations
			}
		}
		e.candidateMu.RUnlock()
		for _, item := range candidateAssets {
			ageScore := minFloat(1, float64(now.Sub(item.FirstSeen))/float64(e.config.MinAssetAge))
			sampleScore := minFloat(1, float64(item.Samples)/float64(e.config.MinAssetSamples))
			item.Readiness = .45*ageScore + .55*sampleScore
			item.Mature = false
			out = append(out, *item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Readiness < out[j].Readiness })
	return out
}

func (e *Engine) IsTrustedAsset(assetID string, now time.Time) bool {
	for _, item := range e.assetMaturities(now, false) {
		if item.AssetID == assetID {
			return item.Mature
		}
	}
	return false
}

func (e *Engine) IsTrustedIP(sensorID, ip string, now time.Time) bool {
	if sensorID == "" {
		sensorID = e.config.SensorID
	}
	return e.IsTrustedAsset(e.resolveIdentity(sensorID, ip), now)
}

func (e *Engine) bucketsPerDay() int {
	expected := int((24 * time.Hour) / e.config.BucketDuration)
	if expected < 1 {
		expected = 1
	}
	return expected
}

func (e *Engine) timeCoverage() float64 {
	buckets := make(map[uint16]struct{})
	for i := range e.assetShards {
		e.assetShards[i].mu.RLock()
		for _, profile := range e.assetShards[i].profiles {
			if profile.Key.Context == "production" || profile.Key.Context == "" {
				buckets[profile.Key.TimeBucket] = struct{}{}
			}
		}
		e.assetShards[i].mu.RUnlock()
	}
	return minFloat(1, float64(len(buckets))/float64(e.bucketsPerDay()))
}

func (e *Engine) recordPatternCreated(at time.Time) {
	e.patternMu.Lock()
	e.patternCreated = append(e.patternCreated, at)
	if len(e.patternCreated) > maxPatternHistory {
		e.patternCreated = append([]time.Time(nil), e.patternCreated[len(e.patternCreated)-maxPatternHistory:]...)
	}
	e.patternMu.Unlock()
}

func (e *Engine) newPatternRate(now time.Time) float64 {
	window := e.config.LearningDuration / 10
	if window < time.Minute {
		window = time.Minute
	}
	if window > 30*time.Minute {
		window = 30 * time.Minute
	}
	cutoff := now.Add(-window)
	recent := 0
	e.patternMu.Lock()
	for _, at := range e.patternCreated {
		if !at.Before(cutoff) {
			recent++
		}
	}
	total := len(e.patternCreated)
	e.patternMu.Unlock()
	if total == 0 {
		return 0
	}
	return float64(recent) / float64(total)
}

func (e *Engine) Status(now time.Time) Status {
	mode, started := e.mode(now)
	readiness, ready, reason := e.readiness(now)
	maturity := e.assetMaturities(now, true)
	mature, learning, candidateAssets := 0, 0, 0
	for _, item := range maturity {
		if item.CandidateOnly {
			candidateAssets++
		} else if item.Mature {
			mature++
		} else {
			learning++
		}
	}
	candidates := e.Candidates(maxCandidateStatus)
	e.candidateMu.RLock()
	candidateCount := len(e.candidates)
	e.candidateMu.RUnlock()
	return Status{
		Enabled: e.config.Enabled, Mode: mode, LearningStarted: started,
		LearningEndsAt: started.Add(e.config.LearningDuration), MinimumDuration: e.config.LearningDuration,
		Readiness: readiness, Ready: ready, ReadinessReason: reason,
		Profiles: e.profiles.Load(), AssetProfiles: e.assetProfiles.Load(), MatureAssets: mature, LearningAssets: learning,
		CandidatePatterns: candidateCount, CandidateAssets: candidateAssets, Candidates: candidates, AssetMaturity: maturity,
		NewPatternRate: e.newPatternRate(now), TimeCoverage: e.timeCoverage(), Observed: e.observed.Load(), Dropped: e.dropped.Load(), Excluded: e.excluded.Load(), Evicted: e.evicted.Load(),
	}
}

func (e *Engine) Candidates(limit int) []Candidate {
	e.candidateMu.RLock()
	out := make([]Candidate, 0, len(e.candidates))
	for _, item := range e.candidates {
		candidate := item.Candidate
		candidate.ObservationDays = candidate.ObservationDays[:0]
		for day := range item.days {
			candidate.ObservationDays = append(candidate.ObservationDays, day)
		}
		sort.Strings(candidate.ObservationDays)
		candidate.DistinctDays = len(candidate.ObservationDays)
		candidate.ReadyForPromotion = candidate.Eligible && candidate.Observations >= uint64(e.config.CandidateMinSamples) && candidate.DistinctDays >= e.config.CandidateMinDays
		out = append(out, candidate)
	}
	e.candidateMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Eligible != out[j].Eligible {
			return out[i].Eligible
		}
		if out[i].Observations != out[j].Observations {
			return out[i].Observations > out[j].Observations
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (e *Engine) Revision() uint64 { return e.revision.Load() }

// ApplyLearningExclusion quarantines a flow. During learning it also removes
// any already-collected trusted flow profile for the same base so a hard
// security event cannot poison the baseline simply because the detector ran a
// few microseconds after the learner saw the packet.
func (e *Engine) ApplyLearningExclusion(exclusion core.LearningExclusion) {
	if exclusion.Until.IsZero() {
		exclusion.Until = time.Now().UTC().Add(24 * time.Hour)
	}
	key := exclusionKey(exclusion.SensorID, exclusion.SrcIP, exclusion.DstIP, exclusion.Protocol, exclusion.ServicePort)
	e.exclusionMu.Lock()
	e.exclusions[key] = exclusion.Until
	e.exclusionMu.Unlock()

	// Existing shadow candidates are quarantined immediately too. Security
	// evidence must win over a previously clean candidate observation.
	e.candidateMu.Lock()
	for _, candidate := range e.candidates {
		if exclusionMatches(candidate.Key, exclusion) {
			candidate.Eligible = false
			candidate.Reason = exclusion.Reason
		}
	}
	e.candidateMu.Unlock()

	mode, _ := e.mode(time.Now().UTC())
	if mode != ModeLearning {
		return
	}
	removed := uint64(0)
	for i := range e.shards {
		e.shards[i].mu.Lock()
		for profileKey := range e.shards[i].profiles {
			if exclusionMatches(profileKey, exclusion) {
				delete(e.shards[i].profiles, profileKey)
				removed++
			}
		}
		e.shards[i].mu.Unlock()
	}
	// Remove the peer relationship from asset-level learning as well. We do
	// not blindly delete protocol/port aggregates because those dimensions may
	// be legitimately learned through other peers; peer identity is the
	// security-relevant relationship that must not become trusted.
	srcAsset := e.resolveIdentity(exclusion.SensorID, exclusion.SrcIP)
	dstAsset := e.resolveIdentity(exclusion.SensorID, exclusion.DstIP)
	for i := range e.assetShards {
		e.assetShards[i].mu.Lock()
		for _, profile := range e.assetShards[i].profiles {
			switch profile.Key.AssetID {
			case srcAsset:
				delete(profile.Peers, dstAsset)
			case dstAsset:
				delete(profile.Peers, srcAsset)
			}
		}
		e.assetShards[i].mu.Unlock()
	}
	if removed > 0 {
		e.profiles.Add(^uint64(removed - 1))
		e.revision.Add(1)
	}
}

func exclusionKey(sensor, src, dst, protocol string, port uint16) string {
	return strings.ToLower(sensor + "|" + src + "|" + dst + "|" + protocol + "|" + strconv.Itoa(int(port)))
}

func exclusionMatches(key Key, exclusion core.LearningExclusion) bool {
	if exclusion.SensorID != "" && key.SensorID != exclusion.SensorID {
		return false
	}
	if exclusion.Protocol != "" && !strings.EqualFold(key.Protocol, exclusion.Protocol) && !strings.EqualFold(key.Transport, exclusion.Protocol) {
		return false
	}
	if exclusion.ServicePort != 0 && key.ServicePort != exclusion.ServicePort {
		return false
	}
	return (key.SrcIP == exclusion.SrcIP && key.DstIP == exclusion.DstIP) || (key.SrcIP == exclusion.DstIP && key.DstIP == exclusion.SrcIP)
}

func (e *Engine) isExcluded(key Key, now time.Time) bool {
	e.exclusionMu.Lock()
	defer e.exclusionMu.Unlock()
	for exclusion, until := range e.exclusions {
		if !until.IsZero() && now.After(until) {
			delete(e.exclusions, exclusion)
			continue
		}
		parts := strings.Split(exclusion, "|")
		if len(parts) != 5 {
			continue
		}
		port, _ := strconv.Atoi(parts[4])
		candidate := core.LearningExclusion{SensorID: parts[0], SrcIP: parts[1], DstIP: parts[2], Protocol: parts[3], ServicePort: uint16(port)}
		if exclusionMatches(key, candidate) {
			return true
		}
	}
	return false
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
	e.candidateMu.Lock()
	e.candidates = make(map[string]*candidateState)
	e.candidateMu.Unlock()
	e.exclusionMu.Lock()
	e.exclusions = make(map[string]time.Time)
	e.exclusionMu.Unlock()
	e.patternMu.Lock()
	e.patternCreated = nil
	e.patternMu.Unlock()
	e.startMu.Lock()
	e.learningStarted = time.Time{}
	e.learningComplete = false
	e.startMu.Unlock()
	e.profiles.Store(0)
	e.assetProfiles.Store(0)
	e.observed.Store(0)
	e.dropped.Store(0)
	e.excluded.Store(0)
	e.evicted.Store(0)
	e.revision.Add(1)
}

func (e *Engine) Snapshot(now time.Time) Snapshot {
	mode, started := e.mode(now)
	result := Snapshot{Version: 5, Mode: mode, LearningStarted: started, LearningEndsAt: started.Add(e.config.LearningDuration), CapturedAt: now, Profiles: make([]Profile, 0, e.profiles.Load()), Observed: e.observed.Load(), Dropped: e.dropped.Load(), Excluded: e.excluded.Load(), Evicted: e.evicted.Load(), Candidates: e.Candidates(0), MinStatSamples: e.config.MinStatSamples, BucketsPerDay: e.bucketsPerDay()}
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
	e.candidateMu.RLock()
	result.CandidateProfiles = make([]CandidateProfileSnapshot, 0, len(e.candidates))
	for id, candidate := range e.candidates {
		profile := candidate.profile
		profile.Operations = make(map[string]uint64, len(candidate.profile.Operations))
		for operation, count := range candidate.profile.Operations {
			profile.Operations[operation] = count
		}
		result.CandidateProfiles = append(result.CandidateProfiles, CandidateProfileSnapshot{ID: id, Profile: profile, SrcAsset: candidate.srcAsset, DstAsset: candidate.dstAsset})
	}
	e.candidateMu.RUnlock()
	e.exclusionMu.RLock()
	for key, until := range e.exclusions {
		parts := strings.Split(key, "|")
		if len(parts) != 5 {
			continue
		}
		port, _ := strconv.Atoi(parts[4])
		result.LearningExclusions = append(result.LearningExclusions, LearningExclusionSnapshot{SensorID: parts[0], SrcIP: parts[1], DstIP: parts[2], Protocol: parts[3], ServicePort: uint16(port), Until: until})
	}
	e.exclusionMu.RUnlock()
	return result
}

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
	if snapshot.Version > 5 {
		return fmt.Errorf("unsupported behavior baseline snapshot version %d", snapshot.Version)
	}
	e.Reset()
	for _, profile := range snapshot.Profiles {
		index := hashKey(profile.Key) % shardCount
		copyProfile := profile
		if copyProfile.Operations == nil {
			copyProfile.Operations = make(map[string]uint64)
		}
		e.shards[index].profiles[profile.Key] = &copyProfile
		e.recordPatternCreated(profile.FirstSeen)
	}
	for _, profile := range snapshot.AssetProfiles {
		index := hashAssetKey(profile.Key) % shardCount
		copyProfile := cloneAssetProfile(&profile)
		e.assetShards[index].profiles[profile.Key] = &copyProfile
		for ip := range profile.IPs {
			e.identityByIP[profile.Key.SensorID+"|"+ip] = profile.Key.AssetID
		}
	}
	candidateProfiles := make(map[string]CandidateProfileSnapshot, len(snapshot.CandidateProfiles))
	for _, value := range snapshot.CandidateProfiles {
		candidateProfiles[value.ID] = value
	}
	e.candidateMu.Lock()
	for _, candidate := range snapshot.Candidates {
		days := make(map[string]struct{})
		for _, day := range candidate.ObservationDays {
			if strings.TrimSpace(day) != "" {
				days[day] = struct{}{}
			}
		}
		if len(days) == 0 && !candidate.FirstSeen.IsZero() {
			days[candidate.FirstSeen.UTC().Format("2006-01-02")] = struct{}{}
		}
		if !candidate.LastSeen.IsZero() {
			days[candidate.LastSeen.UTC().Format("2006-01-02")] = struct{}{}
		}
		candidate.DistinctDays = len(days)
		profile := Profile{Key: candidate.Key, FirstSeen: candidate.FirstSeen, LastSeen: candidate.LastSeen, Operations: make(map[string]uint64)}
		srcAsset, dstAsset := "", ""
		if persisted, ok := candidateProfiles[candidate.ID]; ok {
			profile = persisted.Profile
			if profile.Operations == nil {
				profile.Operations = make(map[string]uint64)
			}
			srcAsset, dstAsset = persisted.SrcAsset, persisted.DstAsset
		}
		state := &candidateState{Candidate: candidate, profile: profile, srcAsset: srcAsset, dstAsset: dstAsset, days: days}
		e.candidates[candidate.ID] = state
	}
	e.candidateMu.Unlock()
	e.exclusionMu.Lock()
	for _, exclusion := range snapshot.LearningExclusions {
		if exclusion.Until.IsZero() || exclusion.Until.After(time.Now().UTC()) {
			key := exclusionKey(exclusion.SensorID, exclusion.SrcIP, exclusion.DstIP, exclusion.Protocol, exclusion.ServicePort)
			e.exclusions[key] = exclusion.Until
		}
	}
	e.exclusionMu.Unlock()
	e.profiles.Store(uint64(len(snapshot.Profiles)))
	e.assetProfiles.Store(uint64(len(snapshot.AssetProfiles)))
	e.observed.Store(snapshot.Observed)
	e.dropped.Store(snapshot.Dropped)
	e.excluded.Store(snapshot.Excluded)
	e.evicted.Store(snapshot.Evicted)
	e.startMu.Lock()
	e.learningStarted = snapshot.LearningStarted
	e.learningComplete = snapshot.Mode == ModeMonitoring
	e.startMu.Unlock()
	e.revision.Add(1)
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
	addString(key.DayClass)
	addString(key.Shift)
	addString(key.Context)
	hash ^= uint32(key.ServicePort)
	hash *= 16777619
	hash ^= uint32(key.TimeBucket)
	hash *= 16777619
	return int(hash & 0x7fffffff)
}

func hashAssetKey(key AssetKey) int {
	hash := uint32(2166136261)
	for _, value := range []string{key.SensorID, key.AssetID, key.DayClass, key.Shift, key.Context} {
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

func parseMaintenanceWindows(values []string) []maintenanceWindow {
	var out []maintenanceWindow
	for _, raw := range values {
		raw = strings.TrimSpace(strings.ToLower(raw))
		parts := strings.Split(raw, "@")
		if len(parts) != 2 {
			continue
		}
		times := strings.Split(parts[1], "-")
		if len(times) != 2 {
			continue
		}
		start, ok1 := parseClockMinute(times[0])
		end, ok2 := parseClockMinute(times[1])
		if !ok1 || !ok2 {
			continue
		}
		days := make(map[time.Weekday]bool)
		daySpec := parts[0]
		switch daySpec {
		case "daily", "all":
			for d := time.Sunday; d <= time.Saturday; d++ {
				days[d] = true
			}
		case "weekday", "weekdays":
			for d := time.Monday; d <= time.Friday; d++ {
				days[d] = true
			}
		case "weekend":
			days[time.Saturday], days[time.Sunday] = true, true
		default:
			for _, token := range strings.Split(daySpec, ",") {
				if d, ok := parseWeekday(token); ok {
					days[d] = true
				}
			}
		}
		if len(days) > 0 {
			out = append(out, maintenanceWindow{days: days, startMinute: start, endMinute: end})
		}
	}
	return out
}

func parseClockMinute(value string) (int, bool) {
	p := strings.Split(strings.TrimSpace(value), ":")
	if len(p) != 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(p[0])
	m, err2 := strconv.Atoi(p[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

func parseWeekday(value string) (time.Weekday, bool) {
	names := map[string]time.Weekday{"sun": time.Sunday, "sunday": time.Sunday, "mon": time.Monday, "monday": time.Monday, "tue": time.Tuesday, "tuesday": time.Tuesday, "wed": time.Wednesday, "wednesday": time.Wednesday, "thu": time.Thursday, "thursday": time.Thursday, "fri": time.Friday, "friday": time.Friday, "sat": time.Saturday, "saturday": time.Saturday}
	d, ok := names[strings.TrimSpace(value)]
	return d, ok
}

func (e *Engine) isMaintenance(at time.Time) bool {
	if len(e.maintenance) == 0 {
		return false
	}
	at = at.UTC()
	minute := at.Hour()*60 + at.Minute()
	for _, window := range e.maintenance {
		if !window.days[at.Weekday()] {
			continue
		}
		if window.startMinute <= window.endMinute {
			if minute >= window.startMinute && minute < window.endMinute {
				return true
			}
		} else if minute >= window.startMinute || minute < window.endMinute {
			return true
		}
	}
	return false
}
