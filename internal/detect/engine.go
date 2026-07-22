// Package detect is the anomaly/rule detection layer, currently
// implementing three independent checks (see arpspoof.go, baseline.go,
// icscritical.go), all reported through the same deduplicated Alert
// model (alert.go):
//
//   - ARP spoofing: an IP's claimed MAC changes after being confirmed.
//   - Baseline deviation: two assets communicate in a way never seen
//     during the configured learning window.
//   - ICS critical operations: security-relevant Modbus/S7comm
//     control functions (e.g. S7 PLCStop) flagged by internal/ics.
package detect

import (
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens/internal/core"
	"github.com/zabojnikvlado/otlens/internal/ics"
	"github.com/zabojnikvlado/otlens/internal/logger"
	"go.uber.org/zap"
)

const defaultARPConfirmThreshold = 3

// Engine is the anomaly/rule detection layer: it consumes the
// already-parsed data other engines produce (core.Packet, ics.Message)
// and raises deduplicated Alerts — the same storage-efficient pattern
// as store.Engine's Tags, applied to security findings instead of
// process variables.
type Engine struct {
	mutex sync.RWMutex

	// ARP spoofing state: last confirmed MAC per IP, plus an
	// in-progress candidate MAC + how many times it's repeated,
	// used to debounce against single stray packets (see arpspoof.go).
	knownMAC       map[string]string
	candidateMAC   map[string]string
	candidateCount map[string]int

	// arpConfirmThreshold is how many consecutive conflicting claims
	// for the same IP are required before the new MAC is accepted as
	// the legitimate mapping. This debounces the detector against a
	// single stray/retransmitted packet — real MAC changes (a NIC
	// swap, DHCP handing the IP to a new device) repeat consistently;
	// an attacker's spoofed replies also repeat, but flagging on the
	// very first packet would also flag ordinary transient noise.
	arpConfirmThreshold int

	// Baseline learning state — see baseline.go.
	baselineMode     BaselineMode
	learningStarted  time.Time
	learningDuration time.Duration
	learnedPatterns  map[string]bool
	learnedAssets    map[string]bool

	// eventBus is retained (not just used transiently in Start) so
	// baseline.go can publish core.EventBaselineLearningComplete the
	// moment learning finishes, and asset_unconfirmed.go can react to
	// core.EventAssetUnconfirmed.
	eventBus *core.EventBus

	alerts map[string]*Alert

	// rules holds every configured rule (built-in + custom) — see
	// rules.go. customRuleSeq is the counter behind each new custom
	// rule's "custom-N" ID.
	rules         map[string]*Rule
	customRuleSeq int

	// deceptionScores/honeypotThreshold — see config.Deception and
	// honeypot.go. Read-only after construction, so no lock needed to
	// read them.
	deceptionScores   map[string]int
	honeypotThreshold int
}

// NewEngine creates a detection engine. learningDuration controls
// how long baseline.go spends learning "normal" asset-to-asset
// communication before it starts alerting on anything new — see
// BaselineStatus/handleBaseline. arpConfirmThreshold of 0 or less
// falls back to defaultARPConfirmThreshold.
//
// baselineEnabled false skips the learning phase entirely: the
// engine starts directly in BaselineModeMonitoring with an empty
// learned set, so every device/communication is "new" from the very
// first packet — useful for a deployment where the network's normal
// baseline is already known/trusted and there's no reason to wait
// out a learning window before alerting starts for real.
//
// deceptionScores/honeypotThreshold configure honeypot.go's lateral-
// movement detection — see config.Deception.
func NewEngine(
	learningDuration time.Duration,
	arpConfirmThreshold int,
	baselineEnabled bool,
	deceptionScores map[string]int,
	honeypotThreshold int,
) *Engine {

	if arpConfirmThreshold <= 0 {
		arpConfirmThreshold = defaultARPConfirmThreshold
	}

	if deceptionScores == nil {
		deceptionScores = make(map[string]int)
	}

	e := &Engine{
		knownMAC:       make(map[string]string),
		candidateMAC:   make(map[string]string),
		candidateCount: make(map[string]int),

		arpConfirmThreshold: arpConfirmThreshold,

		learningDuration: learningDuration,
		learnedPatterns:  make(map[string]bool),
		learnedAssets:    make(map[string]bool),

		alerts: make(map[string]*Alert),

		rules: builtinRules(),

		deceptionScores:   deceptionScores,
		honeypotThreshold: honeypotThreshold,
	}

	if !baselineEnabled {

		// Skip straight to monitoring — handleBaseline's lazy
		// learning-start check (`if e.baselineMode == ""`) only fires
		// when the mode is still unset, so setting it here up front
		// means learning never starts at all. asset.Engine finds out
		// via the existing PublishBaselineStateIfEstablished restart-
		// safety call in app.go (which checks exactly this condition
		// — mode already monitoring — regardless of whether that's
		// because learning genuinely finished in an earlier run, or,
		// as here, because it was configured off from the start).
		e.baselineMode = BaselineModeMonitoring

		logger.Log.Info(
			"Baseline learning disabled (baseline.enabled: false) — starting directly in monitoring mode",
		)
	}

	return e
}

func (e *Engine) Start(bus *core.EventBus) {

	logger.Log.Info(
		"Detect engine started",
	)

	e.eventBus = bus

	e.startARPWatch(bus)
	e.startICSWatch(bus)
	e.startBaselineWatch(bus)
	e.startAssetUnconfirmedWatch(bus)
	e.startValueOutOfRangeWatch(bus)
	e.startHoneypotWatch(bus)
	e.startCustomRuleWatch(bus)

}

func (e *Engine) startARPWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok || packet.L4Protocol != "ARP" {
				continue
			}

			e.handleARP(packet)

		}

	}()

}

func (e *Engine) startICSWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventICSMessage)

	go func() {

		for event := range ch {

			msg, ok := event.Data.(ics.Message)

			if !ok {
				continue
			}

			e.handleICS(msg)

		}

	}()

}

func (e *Engine) startBaselineWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleBaseline(packet)

		}

	}()

}

// logNewAlert logs a freshly-created alert and, if internal/export is
// listening (see core.EventAlertRaised's doc comment), publishes it
// for forwarding to an external server. Deliberately called only
// once per unique finding (from each raise*/handle* function's
// !exists branch) — not on every repeat-occurrence Count/LastSeen
// bump — so a chronic, already-known issue doesn't re-flood an
// external SIEM every time it recurs. Caller must hold e.mutex (only
// called from within the handle*/raise* functions).
func (e *Engine) logNewAlert(alert *Alert) {

	logger.Log.Warn(
		"Alert raised",
		zap.String("type", string(alert.Type)),
		zap.String("severity", alert.Severity),
		zap.String("message", alert.Message),
	)

	if e.eventBus != nil {

		// A copy, not the live *alert — internal/export consumes this
		// asynchronously on its own goroutine, potentially well after
		// this call returns (e.g. mid HTTP request to a slow export
		// server). The live pointer is still sitting in e.alerts[key]
		// and gets Count/LastSeen updated on every future occurrence,
		// unguarded by any lock from export's point of view — reading
		// and writing the same struct from two goroutines with no
		// shared lock is a data race regardless of how unlikely a
		// visible symptom is in practice.
		clone := *alert

		e.eventBus.Publish(
			core.Event{
				Type: core.EventAlertRaised,
				Data: &clone,
			},
		)
	}
}

// ApproveAlert marks an existing alert as reviewed and accepted as
// expected/benign (AlertStatusApproved). It reports false if no
// alert with that ID exists (e.g. already evicted, or a stale ID
// from a client's cached view).
func (e *Engine) ApproveAlert(id string) bool {
	return e.setAlertStatus(id, AlertStatusApproved)
}

// ConfirmAlert marks an existing alert as reviewed and confirmed as
// a genuine issue (AlertStatusConfirmed). Reports false under the
// same conditions as ApproveAlert.
func (e *Engine) ConfirmAlert(id string) bool {
	return e.setAlertStatus(id, AlertStatusConfirmed)
}

func (e *Engine) setAlertStatus(id string, status AlertStatus) bool {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[id]

	if !exists {
		return false
	}

	alert.Status = status
	alert.StatusChangedAt = time.Now()

	return true
}

// CountAlerts returns the number of distinct tracked alerts.
func (e *Engine) CountAlerts() int {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return len(e.alerts)
}

// GetAlerts returns a snapshot of every tracked alert. Each element
// is a shallow copy, not a pointer into the live map — see
// asset.Engine.GetAll's doc comment for why that matters (a data
// race between this and setAlertStatus()/logNewAlert()'s Count/
// LastSeen bump otherwise).
func (e *Engine) GetAlerts() []*Alert {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]*Alert, 0, len(e.alerts))

	for _, alert := range e.alerts {

		clone := *alert

		result = append(
			result,
			&clone,
		)

	}

	return result
}

// RestoreAlerts rehydrates the alert map from previously persisted
// Alerts, e.g. at startup after loading from disk.
func (e *Engine) RestoreAlerts(alerts []*Alert) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	for _, alert := range alerts {

		if alert.Status == "" {
			// Data persisted before AlertStatus existed — treat as
			// unreviewed rather than leaving an invalid empty status.
			alert.Status = AlertStatusNew
		}

		e.alerts[alert.ID] = alert
	}
}

// PruneAlerts removes alerts not updated within maxAge (Count/LastSeen
// stop advancing once the underlying condition stops recurring).
// Returns the number removed.
//
// Deliberately NOT pruned by age: learnedPatterns (baseline.go) and
// knownMAC (arpspoof.go). Both represent "this is legitimate,
// already-seen-and-accepted" state, not history — aging them out
// would cause an infrequent-but-perfectly-normal pattern (a monthly
// maintenance job, a rarely-rebooted device re-ARPing) to look
// "new" again after the retention window passes and spuriously
// re-trigger the exact alerts this baseline was built to prevent.
func (e *Engine) PruneAlerts(maxAge time.Duration) int {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)

	removed := 0

	for id, alert := range e.alerts {

		if alert.LastSeen.Before(cutoff) {
			delete(e.alerts, id)
			removed++
		}
	}

	return removed
}

// Clear removes every tracked alert — the admin UI's "wipe database"
// action. Unlike PruneAlerts, this isn't selective; it's
// a full reset. Deliberately does NOT touch baseline learning state
// (learnedPatterns/learnedAssets) or the ARP knownMAC map — those
// represent "what's normal," not alert history, and wiping them
// would force baseline learning to start over and could re-trigger
// spurious ARP-spoof alerts for perfectly legitimate, already-known
// mappings. Also deliberately does NOT touch rules (built-in
// enabled/disabled toggles, or custom rules) — those are
// configuration a person set up on purpose, not observed data; wiping
// the network's observed history shouldn't also silently delete
// someone's custom rules or re-enable ones they'd turned off.
func (e *Engine) Clear() {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.alerts = make(map[string]*Alert)
}

// BaselineSnapshot is the persisted shape of baseline learning
// progress: what mode it's in, when learning started, and every
// pattern/asset learned so far. Restoring this on startup means a
// restart doesn't throw away hours of learning or reset the clock
// back to "just started learning" — and, for LearnedAssets
// specifically, doesn't re-flag every already-known device as
// newly unconfirmed on every restart.
type BaselineSnapshot struct {
	Mode            BaselineMode
	LearningStarted time.Time
	LearnedPatterns map[string]bool
	LearnedAssets   map[string]bool
}

// BaselineSnapshot captures the current baseline state for
// persistence.
func (e *Engine) BaselineSnapshot() BaselineSnapshot {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	patterns := make(map[string]bool, len(e.learnedPatterns))

	for k, v := range e.learnedPatterns {
		patterns[k] = v
	}

	assets := make(map[string]bool, len(e.learnedAssets))

	for k, v := range e.learnedAssets {
		assets[k] = v
	}

	return BaselineSnapshot{
		Mode:            e.baselineMode,
		LearningStarted: e.learningStarted,
		LearnedPatterns: patterns,
		LearnedAssets:   assets,
	}
}

// RestoreBaseline rehydrates baseline learning state from a
// previously persisted snapshot.
func (e *Engine) RestoreBaseline(snapshot BaselineSnapshot) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if snapshot.Mode == "" {
		// Nothing was ever persisted (fresh database) — leave the
		// zero value so handleBaseline starts the clock on the
		// first packet, same as a genuinely first-ever run.
		return
	}

	e.baselineMode = snapshot.Mode
	e.learningStarted = snapshot.LearningStarted

	for k, v := range snapshot.LearnedPatterns {
		e.learnedPatterns[k] = v
	}

	for k, v := range snapshot.LearnedAssets {
		e.learnedAssets[k] = v
	}
}

// KnownMACSnapshot captures the current confirmed IP->MAC mapping
// used by ARP spoofing detection, for persistence. The in-progress
// candidate/debounce state is deliberately not persisted — it's
// only a few packets' worth of transient state, and restarting the
// debounce window on startup is a fine tradeoff for the simplicity
// of not persisting it.
func (e *Engine) KnownMACSnapshot() map[string]string {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make(map[string]string, len(e.knownMAC))

	for k, v := range e.knownMAC {
		result[k] = v
	}

	return result
}

// RestoreKnownMAC rehydrates the confirmed IP->MAC mapping from a
// previously persisted snapshot, so a restart doesn't forget every
// known-good mapping and treat normal traffic as suspicious again.
func (e *Engine) RestoreKnownMAC(knownMAC map[string]string) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	for k, v := range knownMAC {
		e.knownMAC[k] = v
	}
}
