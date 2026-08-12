package asset

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/hostname"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
)

type Engine struct {
	mutex sync.RWMutex

	assets map[string]*Asset

	// eventBus is retained (not just used transiently in Start) so
	// handle() can publish core.EventAssetUnconfirmed the moment it
	// discovers a genuinely new post-baseline device.
	eventBus *core.EventBus

	// baselineEstablished/knownFromBaseline are populated once, from
	// core.EventBaselineLearningComplete (published by internal/detect
	// — see startBaselineWatch). Until baselineEstablished is true,
	// every newly-discovered device defaults to Confirmed: true (there's
	// nothing yet to compare against); afterward, a MAC not in
	// knownFromBaseline is genuinely new and starts unconfirmed.
	baselineEstablished bool
	knownFromBaseline   map[string]bool

	// arpVerified marks a MAC whose IP has ever been confirmed via an
	// explicit ARP self-announcement ("I am this IP, at this MAC" —
	// see handle()'s ARPSrcMAC/ARPSrcIP handling). Once set, non-ARP
	// observations (Ethernet SrcMAC/DstMAC paired with the packet's
	// IP header) are no longer allowed to overwrite that MAC's IP —
	// see Update's doc comment for why this matters.
	arpVerified map[string]bool

	// deceptionScores is IP -> configured Score (config.Deception.
	// Stations) — read-only after construction, so no lock needed to
	// read it. See Asset.Score's doc comment.
	deceptionScores map[string]int

	// honeypotThreshold is config.Deception.HoneypotThreshold — used
	// only to detect a honeypot->not-honeypot transition (see
	// core.EventHoneypotCleared), not to gate anything in this engine
	// directly.
	honeypotThreshold int
}

func canonicalAssetIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || a.IsUnspecified() || a.IsMulticast() {
		return ""
	}
	return a.Unmap().String()
}

func upsertAddressBinding(a *Asset, ip string, at time.Time, verified bool, vlan uint16) {
	if ip == "" {
		return
	}
	for i := range a.Addresses {
		b := &a.Addresses[i]
		if b.IP != ip {
			continue
		}
		if b.FirstSeen.IsZero() || at.Before(b.FirstSeen) {
			b.FirstSeen = at
		}
		if b.LastSeen.IsZero() || at.After(b.LastSeen) {
			b.LastSeen = at
		}
		b.VerificationKnown = true
		if verified {
			b.VerifiedByL2 = true
		}
		if vlan != 0 {
			b.VLANID = vlan
		}
		return
	}
	a.Addresses = append(a.Addresses, AddressBinding{IP: ip, FirstSeen: at, LastSeen: at, VerificationKnown: true, VerifiedByL2: verified, VLANID: vlan})
}

func NewEngine(deceptionScores map[string]int, honeypotThreshold int) *Engine {

	if deceptionScores == nil {
		deceptionScores = make(map[string]int)
	}

	return &Engine{
		assets:            make(map[string]*Asset),
		knownFromBaseline: make(map[string]bool),
		arpVerified:       make(map[string]bool),
		deceptionScores:   deceptionScores,
		honeypotThreshold: honeypotThreshold,
	}

}

// Update records a sighting of mac at ip. fromARP marks whether this
// specific (ip, mac) pairing came from an explicit ARP self-
// announcement (trustworthy — the device is claiming this IP for
// itself) versus being inferred from a packet's Ethernet+IP headers
// (only trustworthy for genuinely local, same-subnet traffic).
//
// For any packet routed through a gateway — which includes ALL
// traffic to/from an off-link address, e.g. pinging 8.8.8.8 — the
// Ethernet-layer MAC on that packet's gateway-facing side is the
// gateway's own MAC, never the remote host's. Naively pairing that
// MAC with the packet's (remote) IP would misattribute the remote
// address to the gateway's asset record — which is exactly what
// used to happen: the gateway's IP would flicker to whatever
// external address was last routed through it, then flicker back
// once other traffic (or a fresh ARP) reasserted its real IP.
//
// Once a MAC's IP has been ARP-verified, it's treated as
// authoritative and permanent: later non-ARP observations for that
// same MAC no longer overwrite it, even if they carry a different
// IP. A first-ever sighting with no ARP history yet still uses
// whatever IP it's given (best-effort, same as before) since there's
// nothing more trustworthy to fall back on until ARP evidence
// arrives.
func (e *Engine) Update(
	ip string,
	mac string,
	hostname string,
	timestamp time.Time,
	fromARP bool,
	fromAnalysis bool,
	vlanID uint16,
) {

	ip = canonicalAssetIP(ip)
	canonical, ok := canonicalMAC(mac)
	if !ok || isMulticastMAC(canonical) {
		return
	}
	mac = canonical

	e.mutex.Lock()
	defer e.mutex.Unlock()

	asset, exists := e.assets[mac]

	// Captured before any mutation below, so the honeypot-transition
	// check after the Score recompute has something to compare
	// against. Meaningless (and unused) when !exists — a brand-new
	// asset has no prior state to have transitioned away from.
	var previousIP string
	var previousScore int
	if exists {
		previousIP = asset.IP
		previousScore = asset.Score
	}

	if !exists {

		confirmed := true

		if e.baselineEstablished && !e.knownFromBaseline[mac] {
			confirmed = false
		}

		asset = &Asset{

			ID: mac,

			MAC: mac,

			IP: ip,

			Hostname: hostname,

			FirstSeen: timestamp,

			Confirmed: confirmed,

			FromAnalysis: fromAnalysis,

			IPVerificationKnown: true,
			IPVerifiedByARP:     fromARP,

			VLANID: vlanID,
		}

		e.assets[mac] = asset

		logger.Log.Info(
			"Asset discovered",
		)

		if !confirmed && e.eventBus != nil {

			e.eventBus.Publish(
				core.Event{
					Type: core.EventAssetUnconfirmed,
					Data: core.UnconfirmedAsset{MAC: mac, IP: ip},
				},
			)
		}

	} else if !fromAnalysis {

		// A live (or IPFIX) sighting of an already-known device
		// permanently clears FromAnalysis, even if the record was
		// first created by a pcap analysis — it's confirmed to
		// currently exist on the real network now, not just a
		// historical snapshot, so it goes back to normal age-based
		// retention like everything else. An analysis-sourced
		// sighting never does the reverse (never sets it back to
		// true) — only live evidence should ever mark something as
		// "no longer just historical".
		asset.FromAnalysis = false
	}

	// A learning reset intentionally keeps inventory but clears what counts as
	// trusted baseline. Once the new learning window closes, an older retained
	// asset that was not seen during that window must become reviewable again
	// when it reappears.
	if exists && e.baselineEstablished && !e.knownFromBaseline[mac] && asset.Confirmed {
		asset.Confirmed = false
		if e.eventBus != nil {
			e.eventBus.Publish(core.Event{Type: core.EventAssetUnconfirmed, Data: core.UnconfirmedAsset{MAC: mac, IP: ip}})
		}
	}

	if ip != "" {
		// Do not let routed Ethernet/IP observations create secondary aliases
		// after this NIC has an authoritative ARP/NDP identity. Before the first
		// authoritative claim we keep one provisional path; once L2 proof arrives,
		// discard other unverified aliases learned from routed traffic.
		if fromARP {
			if !e.arpVerified[mac] {
				kept := asset.Addresses[:0]
				for _, b := range asset.Addresses {
					if b.VerifiedByL2 || b.IP == ip {
						kept = append(kept, b)
					}
				}
				asset.Addresses = kept
			}
			upsertAddressBinding(asset, ip, timestamp, true, vlanID)
		} else if !e.arpVerified[mac] {
			upsertAddressBinding(asset, ip, timestamp, false, vlanID)
		}

		if fromARP {

			asset.IP = ip
			asset.IPVerificationKnown = true
			asset.IPVerifiedByARP = true
			e.arpVerified[mac] = true

		} else if !e.arpVerified[mac] {

			// A device can pick up a new IP (DHCP renewal etc.) —
			// keep the asset record current rather than stuck on the
			// first IP seen. Only applies pre-ARP-verification; see
			// the doc comment above for why a verified MAC's IP is
			// locked after that point.
			asset.IP = ip
		}
	}

	// Only overwrite with a non-zero VLAN tag — a device captured
	// sometimes on a tagged path and sometimes on an untagged one
	// (e.g. the capture point strips the tag on some packets but not
	// others) shouldn't have its last-known real VLAN wiped back to
	// "untagged" by whichever observation happened to arrive last.
	if vlanID != 0 {
		asset.VLANID = vlanID
	}

	// Recompute Score against the asset's current IP every time, not
	// just once at creation — deliberately not "sticky": if a device
	// moves off a configured deception station's IP (DHCP renewal
	// etc.), the decoy property was about that IP address, not the
	// device wherever it ends up, so the score should follow suit
	// rather than staying pinned to a stale match.
	if score, ok := e.deceptionScores[asset.IP]; ok {
		asset.Score = score
	} else {
		asset.Score = 1
	}

	// The device that used to sit on a configured decoy IP just moved
	// off it (or, less commonly, its score genuinely dropped) —
	// previousIP is what actually appeared as SrcIP/DstIP on any
	// lateral-movement/probed alert raised while it was a honeypot, so
	// that's the identity internal/detect needs to clear those against,
	// not asset.IP (which may already be the new, non-honeypot address).
	if exists && e.eventBus != nil {
		wasHoneypot := previousScore >= e.honeypotThreshold
		isHoneypot := asset.Score >= e.honeypotThreshold
		if wasHoneypot && (!isHoneypot || asset.IP != previousIP) {
			e.eventBus.Publish(
				core.Event{
					Type: core.EventHoneypotCleared,
					Data: core.HoneypotCleared{IP: previousIP},
				},
			)
		}
	}

	asset.LastSeen = timestamp

	asset.PacketCount++

}

func (e *Engine) Count() int {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return len(e.assets)

}

// Restore rehydrates the engine's in-memory state from previously
// persisted assets, e.g. at startup after loading from disk. Unlike
// Update, this doesn't bump PacketCount/LastSeen — it's replacing the
// map contents with known-good data, not observing new traffic.
//
// Confirmed is preserved exactly as persisted. An unreviewed asset is a
// security workflow state and must not silently become trusted merely because
// the sensor restarted.
//
// Score is also recomputed against the current config on every
// restore, not just trusted as-persisted — see the loop body.
func (e *Engine) Restore(assets []*Asset) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Restore is a replacement operation, not a merge. Reset paths call
	// Restore(nil), so retaining the previous map here made every reset a no-op.
	e.assets = make(map[string]*Asset, len(assets))
	// Rebuild the ARP trust guard as well. Without this, a restored asset could
	// have its persisted IP replaced by the first routed/non-ARP observation
	// seen after restart, even though before restart that same MAC/IP was
	// protected by arpVerified. A later real ARP observation is still allowed
	// to move the asset to a new DHCP/static address.
	e.arpVerified = make(map[string]bool, len(assets))

	for _, a := range assets {
		if a == nil {
			continue
		}
		mac, ok := canonicalMAC(a.MAC)
		if !ok || isMulticastMAC(mac) {
			continue
		}
		a.MAC = mac
		a.ID = mac
		a.IP = canonicalAssetIP(a.IP)
		clean := a.Addresses[:0]
		seen := map[string]bool{}
		for _, b := range a.Addresses {
			b.IP = canonicalAssetIP(b.IP)
			if b.IP == "" || seen[b.IP] {
				continue
			}
			seen[b.IP] = true
			clean = append(clean, b)
		}
		a.Addresses = clean
		if a.IP != "" && !seen[a.IP] {
			a.Addresses = append(a.Addresses, AddressBinding{IP: a.IP, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, VerificationKnown: a.IPVerificationKnown, VerifiedByL2: a.IPVerifiedByARP, VLANID: a.VLANID})
		}

		// Recompute against the *current* config.Deception.Stations,
		// not whatever Score happened to be persisted — otherwise a
		// changed/removed honeypot IP would keep showing its old
		// classification until this asset is seen again in live
		// traffic (Update() does the same recompute, but only on the
		// next observation, which could be a long wait for a quiet
		// device). Same logic as Update()'s.
		if score, ok := e.deceptionScores[a.IP]; ok {
			a.Score = score
		} else {
			a.Score = 1
		}

		e.assets[a.MAC] = a
		if a.MAC != "" && a.IP != "" {
			if a.IPVerificationKnown {
				e.arpVerified[a.MAC] = a.IPVerifiedByARP
			} else {
				// Compatibility with v24 snapshots written before binding provenance
				// was persisted. Preserve the previous conservative restart behavior
				// rather than risking a routed packet reassigning a gateway asset.
				e.arpVerified[a.MAC] = true
			}
		}
	}
}

// Prune removes assets not seen within maxAge, so a long-running
// process doesn't accumulate devices (guest laptops, once-off
// scanners, etc.) forever. Returns the number removed. A maxAge of 0
// disables pruning entirely — the caller is expected to check that
// before calling.
//
// Assets with FromAnalysis still set (never confirmed by live
// traffic) are skipped regardless of age — see Asset.FromAnalysis's
// doc comment for why a deliberately-analyzed historical snapshot
// shouldn't be aged out by wall-clock retention.
func (e *Engine) Prune(maxAge time.Duration) int {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)

	removed := 0

	for mac, a := range e.assets {

		if a.FromAnalysis {
			continue
		}

		if a.LastSeen.Before(cutoff) {
			delete(e.assets, mac)
			delete(e.arpVerified, mac)
			removed++
		}
	}

	return removed
}

// Delete removes a single asset by MAC, for manual cleanup from the
// admin UI (e.g. a known test device or one-off scanner) outside the
// normal age-based Prune. Returns false if no asset with that MAC
// exists.
func (e *Engine) Delete(mac string) bool {

	canonical, ok := canonicalMAC(mac)
	if !ok {
		return false
	}
	mac = canonical
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if _, exists := e.assets[mac]; !exists {
		return false
	}

	delete(e.assets, mac)
	delete(e.arpVerified, mac)
	delete(e.knownFromBaseline, mac)

	return true
}

// Get returns a snapshot of one tracked asset, or nil if no asset
// with that MAC exists. A shallow copy, not a pointer into the live
// map — see GetAll's doc comment for why that matters.
func (e *Engine) Get(mac string) *Asset {

	canonical, ok := canonicalMAC(mac)
	if !ok {
		return nil
	}
	mac = canonical
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	a, exists := e.assets[mac]

	if !exists {
		return nil
	}

	clone := *a

	return &clone
}

// Confirm marks a device as reviewed/known — the Assets tab's
// Confirm action for a device flagged unconfirmed (see Update).
// Returns false if no asset with that MAC exists.
func (e *Engine) Confirm(mac string) bool {

	canonical, ok := canonicalMAC(mac)
	if !ok {
		return false
	}
	mac = canonical
	e.mutex.Lock()
	defer e.mutex.Unlock()

	a, exists := e.assets[mac]

	if !exists {
		return false
	}

	a.Confirmed = true
	// Explicit analyst confirmation is trusted even if this asset was absent
	// from the most recent passive learning window.
	e.knownFromBaseline[mac] = true

	return true
}

// ResetBaseline clears only learning/trust classification. Inventory remains;
// Data Management's asset/database resets decide separately whether to remove
// asset records.
func (e *Engine) ResetBaseline() {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.baselineEstablished = false
	e.knownFromBaseline = make(map[string]bool)
}

// Clear removes every tracked asset — the admin UI's "wipe database"
// action. Unlike Delete/Prune, this isn't selective; it's a full
// reset.
func (e *Engine) Clear() {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.assets = make(map[string]*Asset)
	e.arpVerified = make(map[string]bool)
	e.knownFromBaseline = make(map[string]bool)
	e.baselineEstablished = false
}

// Start subscribes directly to parsed packets and learns assets from
// both the source and destination MAC/IP of every packet, the same
// way the flow and debug engines each independently consume
// EventPacketParsed. It also subscribes to core.EventHostnameSeen
// (internal/hostname's mDNS/DHCP findings) to enrich an
// already-known asset's Hostname field, and to
// core.EventBaselineLearningComplete (internal/detect's baseline
// tracking) to know which devices count as already-known once
// learning finishes.
func (e *Engine) Start(
	bus *core.EventBus,
) {

	e.eventBus = bus

	e.startPacketWatch(bus)
	e.startHostnameWatch(bus)
	e.startBaselineWatch(bus)

}

func (e *Engine) startPacketWatch(bus *core.EventBus) {

	ch := bus.Subscribe(
		core.EventPacketParsed,
	)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handle(packet)

		}

	}()

}

func (e *Engine) startHostnameWatch(bus *core.EventBus) {

	ch := bus.Subscribe(
		core.EventHostnameSeen,
	)

	go func() {

		for event := range ch {

			obs, ok := event.Data.(hostname.Observation)

			if !ok {
				continue
			}

			e.handleHostname(obs)

		}

	}()

}

// handleHostname applies a hostname observation to an already-known
// asset. It deliberately does NOT create a new asset record for a
// MAC it hasn't seen via regular traffic yet — asset discovery stays
// solely the job of handle()/Update() above; this only enriches.
func (e *Engine) handleHostname(obs hostname.Observation) {

	if obs.MAC == "" || obs.Hostname == "" {
		return
	}
	mac, ok := canonicalMAC(obs.MAC)
	if !ok {
		return
	}
	obs.MAC = mac

	e.mutex.Lock()
	defer e.mutex.Unlock()

	asset, exists := e.assets[obs.MAC]

	if !exists {
		return
	}

	if asset.Hostname != obs.Hostname {

		asset.Hostname = obs.Hostname

		logger.Log.Info(
			"Asset hostname resolved",
		)
	}
}

func (e *Engine) startBaselineWatch(bus *core.EventBus) {

	ch := bus.Subscribe(
		core.EventBaselineLearningComplete,
	)

	go func() {

		for event := range ch {

			bc, ok := event.Data.(core.BaselineComplete)

			if !ok {
				continue
			}

			e.handleBaselineComplete(bc)

		}

	}()

}

// handleBaselineComplete records the full set of devices seen during
// baseline learning (published once by internal/detect right when
// learning finishes — see detect.Engine.publishBaselineComplete).
// From this point on, Update decides Confirmed based on membership
// in this set for any newly-discovered device.
func (e *Engine) handleBaselineComplete(bc core.BaselineComplete) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	for _, mac := range bc.LearnedAssetMACs {
		if canonical, ok := canonicalMAC(mac); ok {
			e.knownFromBaseline[canonical] = true
		}
	}

	e.baselineEstablished = true

	logger.Log.Info(
		"Baseline established for asset confirmation",
	)
}

func (e *Engine) handle(packet core.Packet) {

	// A single packet can identify the same device through more than
	// one path — e.g. for an ARP packet, the Ethernet SrcMAC and the
	// ARP payload's ARPSrcMAC are almost always the same address.
	// Collecting observations here and deduping by MAC before
	// calling Update (which bumps PacketCount/LastSeen once per
	// call) is what keeps PacketCount an accurate count of packets
	// seen, not "sightings across every field that happened to name
	// this MAC".
	type observation struct {
		ip      string
		mac     string
		fromARP bool
	}

	var observations []observation

	// Hostname isn't known from raw packet parsing alone (that would
	// need DHCP/DNS/mDNS parsing); left empty for now.
	if packet.SrcMAC != "" && !isMulticastMAC(packet.SrcMAC) {
		observations = append(observations, observation{ip: packet.SrcIP, mac: packet.SrcMAC})
	}

	if packet.DstMAC != "" && !isMulticastMAC(packet.DstMAC) {
		observations = append(observations, observation{ip: packet.DstIP, mac: packet.DstMAC})
	}

	// ARP carries an explicit "I am this IP, at this MAC" claim that
	// the two sightings above miss entirely: packet.SrcIP/DstIP are
	// only populated by the IPv4/IPv6 parser, never by the ARP
	// parser, so a device that mostly sends ARP requests without
	// much unicast IP traffic would otherwise show up as MAC-only,
	// with IP permanently empty. Only ARPSrc* is used here (not
	// ARPDst*) — the destination side of an ARP request is the IP
	// being asked about, paired with an all-zeros placeholder MAC
	// (not yet known), which would be wrong to record as if it were
	// a real device.
	if packet.ARPSrcMAC != "" && !isMulticastMAC(packet.ARPSrcMAC) &&
		packet.ARPSrcIP != "" && packet.ARPSrcIP != "0.0.0.0" {

		observations = append(observations, observation{ip: packet.ARPSrcIP, mac: packet.ARPSrcMAC, fromARP: true})
	}

	// IPv6 Neighbor Discovery is authoritative L2 ownership just like ARP.
	if packet.NDPSrcMAC != "" && !isMulticastMAC(packet.NDPSrcMAC) && packet.NDPSrcIP != "" && packet.NDPSrcIP != "::" {
		observations = append(observations, observation{ip: packet.NDPSrcIP, mac: packet.NDPSrcMAC, fromARP: true})
	}

	// Merge by MAC: prefer an ARP-sourced observation over a non-ARP
	// one (see Update's doc comment for why — briefly, ARP is the
	// only kind trustworthy enough to overwrite an already-verified
	// IP), and otherwise prefer whichever observation actually
	// carries an IP (the ARP payload is often the only source of one
	// for an otherwise IP-less ARP packet).
	byMAC := make(map[string]observation, len(observations))

	for _, obs := range observations {

		existing, seen := byMAC[obs.mac]

		switch {

		case !seen:
			byMAC[obs.mac] = obs

		case obs.fromARP && !existing.fromARP:
			byMAC[obs.mac] = obs

		case !existing.fromARP && existing.ip == "" && obs.ip != "":
			byMAC[obs.mac] = obs
		}
	}

	for mac, obs := range byMAC {
		e.Update(obs.ip, mac, "", packet.Timestamp, obs.fromARP, packet.FromAnalysis, packet.VLANID)
	}
}

func canonicalMAC(mac string) (string, bool) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return hw.String(), true
}

// isMulticastMAC reports whether a MAC address is a multicast or
// broadcast address (ff:ff:ff:ff:ff:ff is a special case of
// multicast). These addresses identify a class of receivers, not a
// single physical device, so they must not be recorded as assets.
func isMulticastMAC(mac string) bool {

	hw, err := net.ParseMAC(mac)

	if err != nil || len(hw) == 0 {
		return false
	}

	return hw[0]&0x01 != 0
}

// GetAll returns a snapshot of every tracked asset. Each element is
// a shallow copy, not a pointer into the live map — without that,
// the lock here only protects the map iteration itself; the moment
// this function returns, a caller (the periodic persist flush, an
// API handler JSON-marshaling the result) can be reading a field on
// one of these structs at the exact same time Update() is writing to
// that same field, unguarded by any lock, on a live-traffic
// goroutine. A shallow copy is enough here — nothing on Asset is a
// slice/map that gets mutated in place after assignment (only ever
// wholesale-reassigned), so there's no deeper structure to worry
// about aliasing.
func (e *Engine) GetAll() []*Asset {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]*Asset, 0, len(e.assets))

	for _, asset := range e.assets {

		clone := *asset
		// Address bindings are a slice and therefore require a deep copy. A
		// shallow struct copy would share the live backing array with packet
		// capture while topology/telemetry marshals the snapshot.
		clone.Addresses = append([]AddressBinding(nil), asset.Addresses...)

		result = append(
			result,
			&clone,
		)

	}

	return result
}
