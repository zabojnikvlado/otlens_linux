// Package persist is the disk persistence layer, backed by SQLite
// (db.go's thin wrapper) so a restart doesn't lose every asset,
// flow, tag, and alert that other engines only keep in memory.
// Snapshotter (snapshotter.go) is the orchestrator: it restores
// state at startup, flushes it periodically (not per-packet — see
// its doc comment for why), and prunes anything past the configured
// retention window before every flush.
package persist

import (
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/asset"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/flow"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/store"
	"go.uber.org/zap"
)

const (
	bucketAssets = "assets"
	bucketFlows  = "flows"
	bucketTags   = "tags"
	bucketAlerts = "alerts"
	bucketRules  = "rules"

	// bucketMeta holds single-blob state that isn't naturally a keyed
	// collection — see the blobKey* constants below.
	bucketMeta = "meta"

	blobKeyTagChanges = "tag_changes"
	blobKeyTagEvents  = "tag_events"
	blobKeyBaseline   = "baseline"
	blobKeyKnownMAC   = "arp_known_mac"
)

var allBuckets = []string{bucketAssets, bucketFlows, bucketTags, bucketAlerts, bucketRules, bucketMeta}

// Snapshotter periodically writes each engine's current in-memory
// state to a SQLite database, and restores it back at startup. This is
// the write side of the "Nozomi-style" storage design already used
// throughout OTLens: because every engine already dedups aggressively
// in memory (one row per asset/flow/tag/alert, not one row per
// packet), writing a full snapshot every few seconds is cheap —
// unlike writing to disk on every single packet, which would both
// hammer the disk and bottleneck packet processing (SQLite commits a
// full fsync per write transaction, so per-packet writes would cap
// throughput at a few hundred packets/sec on typical disks).
//
// The tradeoff: up to one flush interval's worth of the very latest
// counters/state can be lost if the process is killed uncleanly
// between flushes. Given the underlying data (poll counts, latest
// values) is itself constantly being re-observed from live traffic,
// losing a few seconds of it on an unclean shutdown is an acceptable
// price for not slowing down capture.
type Snapshotter struct {
	db *DB

	assetEngine  *asset.Engine
	flowEngine   *flow.Engine
	storeEngine  *store.Engine
	detectEngine *detect.Engine

	interval time.Duration

	// retention is how far back to keep records — anything with a
	// LastSeen/Timestamp older than this is pruned from memory (and,
	// via the next flush's syncKeyed, from disk) before every write.
	// Zero disables pruning entirely (keep everything forever).
	retention time.Duration
}

// NewSnapshotter opens (creating if necessary) the SQLite database at
// path and prepares it to snapshot the given engines. retention of 0
// disables age-based pruning; any positive duration is the maximum
// age a record can reach before being dropped.
func NewSnapshotter(
	path string,
	assetEngine *asset.Engine,
	flowEngine *flow.Engine,
	storeEngine *store.Engine,
	detectEngine *detect.Engine,
	interval time.Duration,
	retention time.Duration,
) (*Snapshotter, error) {

	db, err := Open(path)

	if err != nil {
		return nil, err
	}

	for _, bucket := range allBuckets {

		if err := db.EnsureBucket(bucket); err != nil {
			db.Close()
			return nil, err
		}
	}

	return &Snapshotter{
		db: db,

		assetEngine:  assetEngine,
		flowEngine:   flowEngine,
		storeEngine:  storeEngine,
		detectEngine: detectEngine,

		interval:  interval,
		retention: retention,
	}, nil
}

// Restore loads all previously persisted state back into the live
// engines. Call once at startup, before the engines' Start().
func (s *Snapshotter) Restore() error {

	assets, err := loadKeyed[*asset.Asset](s.db, bucketAssets)

	if err != nil {
		return err
	}

	s.assetEngine.Restore(assets)

	flows, err := loadKeyed[*flow.Flow](s.db, bucketFlows)

	if err != nil {
		return err
	}

	s.flowEngine.Restore(flows)

	tags, err := loadKeyed[*store.Tag](s.db, bucketTags)

	if err != nil {
		return err
	}

	s.storeEngine.RestoreTags(tags)

	alerts, err := loadKeyed[*detect.Alert](s.db, bucketAlerts)

	if err != nil {
		return err
	}

	s.detectEngine.RestoreAlerts(alerts)

	rules, err := loadKeyed[*detect.Rule](s.db, bucketRules)

	if err != nil {
		return err
	}

	s.detectEngine.RestoreRules(rules)

	var changes []store.ValueChange

	if err := loadBlob(s.db, bucketMeta, blobKeyTagChanges, &changes); err != nil {
		return err
	}

	s.storeEngine.RestoreValueChanges(changes)

	var events []store.ControlEvent

	if err := loadBlob(s.db, bucketMeta, blobKeyTagEvents, &events); err != nil {
		return err
	}

	s.storeEngine.RestoreControlEvents(events)

	var baseline detect.BaselineSnapshot

	if err := loadBlob(s.db, bucketMeta, blobKeyBaseline, &baseline); err != nil {
		return err
	}

	s.detectEngine.RestoreBaseline(baseline)

	var knownMAC map[string]string

	if err := loadBlob(s.db, bucketMeta, blobKeyKnownMAC, &knownMAC); err != nil {
		return err
	}

	if knownMAC != nil {
		s.detectEngine.RestoreKnownMAC(knownMAC)
	}

	logger.Log.Info(
		"Restored persisted state from disk",
		zap.Int("assets", len(assets)),
		zap.Int("flows", len(flows)),
		zap.Int("tags", len(tags)),
		zap.Int("alerts", len(alerts)),
	)

	return nil
}

// Start begins periodic flushing to disk until the process exits.
func (s *Snapshotter) Start() {

	go func() {

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for range ticker.C {

			if err := s.flush(); err != nil {

				logger.Log.Warn(
					"Snapshot flush failed",
					zap.Error(err),
				)
			}

		}

	}()

}

// Flush immediately writes the current state of every engine to
// disk. Start() calls this on a timer; it's also exported so a
// graceful-shutdown path can call it one last time before exit.
func (s *Snapshotter) Flush() error {
	return s.flush()
}

func (s *Snapshotter) flush() error {

	s.prune()

	if err := syncKeyed(s.db, bucketAssets, s.assetEngine.GetAll(), func(a *asset.Asset) string {
		return a.MAC
	}); err != nil {
		return err
	}

	if err := syncKeyed(s.db, bucketFlows, s.flowEngine.GetAll(), func(f *flow.Flow) string {
		return f.ID
	}); err != nil {
		return err
	}

	if err := syncKeyed(s.db, bucketTags, s.storeEngine.GetTags(), func(t *store.Tag) string {
		return t.Key
	}); err != nil {
		return err
	}

	if err := syncKeyed(s.db, bucketAlerts, s.detectEngine.GetAlerts(), func(a *detect.Alert) string {
		return a.ID
	}); err != nil {
		return err
	}

	if err := syncKeyed(s.db, bucketRules, s.detectEngine.GetRuleConfigs(), func(r *detect.Rule) string {
		return r.ID
	}); err != nil {
		return err
	}

	if err := saveBlob(s.db, bucketMeta, blobKeyTagChanges, s.storeEngine.GetValueChanges()); err != nil {
		return err
	}

	if err := saveBlob(s.db, bucketMeta, blobKeyTagEvents, s.storeEngine.GetControlEvents()); err != nil {
		return err
	}

	if err := saveBlob(s.db, bucketMeta, blobKeyBaseline, s.detectEngine.BaselineSnapshot()); err != nil {
		return err
	}

	if err := saveBlob(s.db, bucketMeta, blobKeyKnownMAC, s.detectEngine.KnownMACSnapshot()); err != nil {
		return err
	}

	return nil
}

// prune removes records older than the configured retention window
// from every engine's in-memory state, before that state gets
// written to disk. This — not the count-based appendBounded caps —
// is what actually keeps both RAM and the SQLite database from growing
// without limit over a long-running deployment. A retention of 0
// disables this (keep everything forever).
//
// Not pruned here: baseline.learnedPatterns and detect's ARP
// knownMAC map — see PruneAlerts's doc comment for why aging those
// out would be actively harmful (re-triggering alerts for perfectly
// normal, just infrequent, activity).
//
// Also not pruned by age: any asset/flow/tag still flagged
// FromAnalysis (see asset.Asset's doc comment) — records that came
// from the admin UI's "analyze an uploaded pcap" workflow and
// haven't yet been confirmed by live traffic. That data legitimately
// carries the file's own original historical timestamps (a pcap
// captured last month, analyzed today), so it's exempted at the
// per-record level in each engine's Prune/PruneTags rather than by
// pausing pruning globally based on whether capture happens to be
// running — pausing everything would also block ordinary age-based
// cleanup of genuinely stale live data for as long as capture
// happened to be stopped, which isn't what retention is for.
func (s *Snapshotter) prune() {

	if s.retention <= 0 {
		return
	}

	removedAssets := s.assetEngine.Prune(s.retention)
	removedFlows := s.flowEngine.Prune(s.retention)
	removedTags := s.storeEngine.PruneTags(s.retention)
	s.storeEngine.PruneHistory(s.retention)
	removedAlerts := s.detectEngine.PruneAlerts(s.retention)

	total := removedAssets + removedFlows + removedTags + removedAlerts

	if total > 0 {

		logger.Log.Info(
			"Pruned records past retention window",
			zap.Duration("retention", s.retention),
			zap.Int("assets", removedAssets),
			zap.Int("flows", removedFlows),
			zap.Int("tags", removedTags),
			zap.Int("alerts", removedAlerts),
		)
	}
}

// Close flushes one last time and closes the underlying SQLite database.
// Call during graceful shutdown.
func (s *Snapshotter) Close() error {

	if err := s.flush(); err != nil {

		logger.Log.Warn(
			"Final snapshot flush failed",
			zap.Error(err),
		)
	}

	return s.db.Close()
}
