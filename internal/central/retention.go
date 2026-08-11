package central

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// RetentionConfig mirrors config.CentralConfig.DatabaseRetention — kept
// as its own type here so this package doesn't need to import
// internal/config just for these seven fields.
type RetentionConfig struct {
	Enabled              bool
	Interval             time.Duration
	TelemetryDays        int
	AlertsDays           int
	AuditDays            int
	MaxDatabaseSizeGB    int
	TargetDatabaseSizeGB int
	DeleteBatchSize      int
}

// retentionTable is one table this system is allowed to prune, and
// nothing else in the schema is ever touched by it — see the doc
// comments on config.CentralConfig.DatabaseRetention and on each of
// these tables in the embedded schema for why. ageColumn is what "oldest"
// means for that table: last observed activity, not row creation, so a
// pair/alert that's still actively happening never ages out just because
// it was first recorded a while ago.
type retentionTable struct {
	name      string
	ageColumn string
	ageDays   func(cfg RetentionConfig) int
}

var retentionTables = []retentionTable{
	{"flow_observations", "bucket_end", func(c RetentionConfig) int { return c.TelemetryDays }},
	{"dns_observations", "observed_at", func(c RetentionConfig) int { return c.TelemetryDays }},
	{"smb_observations", "observed_at", func(c RetentionConfig) int { return c.TelemetryDays }},
	{"protocol_observations", "observed_at", func(c RetentionConfig) int { return c.TelemetryDays }},
	{"topology_edges", "last_seen", func(c RetentionConfig) int { return c.TelemetryDays }},
	{"topology_nodes", "last_seen", func(c RetentionConfig) int { return c.TelemetryDays }},
	{"analysis_jobs", "created_at", func(c RetentionConfig) int { return c.TelemetryDays }},
	{"alert_history", "last_seen", func(c RetentionConfig) int { return c.AlertsDays }},
	{"audit_log", "created_at", func(c RetentionConfig) int { return c.AuditDays }},
}

// RunRetention is the whole retention sweep: age-based pruning per
// category first (each table against its own *_days cutoff), then —
// only if the tables this system can touch are still over
// MaxDatabaseSizeGB after that — a size backstop that deletes the
// globally oldest rows across all five tables (not a fixed per-category
// priority order) until back at or under TargetDatabaseSizeGB. Meant to
// be called on a ticker (see cmd/otlens-central/main.go); logs a summary
// either way and never panics — a failed sweep just tries again next
// interval.
func (r *Repository) RunRetention(ctx context.Context, cfg RetentionConfig) {
	if !cfg.Enabled {
		return
	}

	ageDeleted, err := r.ageBasedRetention(ctx, cfg)
	if err != nil {
		log.Printf("retention: age-based sweep failed: %v", err)
	}
	if total := sumCounts(ageDeleted); total > 0 {
		log.Printf("retention: age-based sweep removed %d rows: %v", total, ageDeleted)
	}

	sizeGB, err := r.retentionTablesSizeGB(ctx)
	if err != nil {
		log.Printf("retention: size check failed: %v", err)
		return
	}
	if sizeGB <= float64(cfg.MaxDatabaseSizeGB) {
		return
	}

	log.Printf("retention: tracked tables at %.1fGB (max %dGB) — trimming oldest rows toward %dGB", sizeGB, cfg.MaxDatabaseSizeGB, cfg.TargetDatabaseSizeGB)
	sizeDeleted, err := r.sizeBasedRetention(ctx, cfg)
	if err != nil {
		log.Printf("retention: size-based sweep failed: %v", err)
	}
	if total := sumCounts(sizeDeleted); total > 0 {
		log.Printf("retention: size-based sweep removed %d rows: %v", total, sizeDeleted)
	}
}

func sumCounts(m map[string]int64) int64 {
	var total int64
	for _, n := range m {
		total += n
	}
	return total
}

// ageBasedRetention deletes, per table, whatever's older than that
// table's configured *_days cutoff — unconditionally, regardless of
// database size. A days value of 0 (or less) disables that table's
// age-based cutoff entirely (it's still subject to the size backstop).
func (r *Repository) ageBasedRetention(ctx context.Context, cfg RetentionConfig) (map[string]int64, error) {
	deleted := make(map[string]int64, len(retentionTables))
	for _, t := range retentionTables {
		days := t.ageDays(cfg)
		if days <= 0 {
			continue
		}
		for {
			select {
			case <-ctx.Done():
				return deleted, ctx.Err()
			default:
			}
			n, err := r.deleteOldestBatch(ctx, t.name, t.ageColumn, cfg.DeleteBatchSize,
				fmt.Sprintf("%s < NOW() - make_interval(days => %d)", t.ageColumn, days))
			if err != nil {
				return deleted, fmt.Errorf("%s: %w", t.name, err)
			}
			deleted[t.name] += n
			if n < int64(cfg.DeleteBatchSize) {
				break // fewer than a full batch came back — nothing older left
			}
			time.Sleep(200 * time.Millisecond) // let other DB activity through between batches
		}
	}
	return deleted, nil
}

// sizeBasedRetention repeatedly finds whichever of the five tables
// currently holds the single oldest row (comparing across all of them,
// not a fixed priority order) and deletes a batch of that table's oldest
// rows, until the tracked tables' combined size is back at or under
// TargetDatabaseSizeGB. This runs regardless of each row's age — it's a
// backstop for "the *_days cutoffs weren't enough to keep up," so it has
// to be willing to remove things that haven't technically expired yet.
func (r *Repository) sizeBasedRetention(ctx context.Context, cfg RetentionConfig) (map[string]int64, error) {
	deleted := make(map[string]int64, len(retentionTables))
	for {
		select {
		case <-ctx.Done():
			return deleted, ctx.Err()
		default:
		}

		sizeGB, err := r.retentionTablesSizeGB(ctx)
		if err != nil {
			return deleted, err
		}
		if sizeGB <= float64(cfg.TargetDatabaseSizeGB) {
			return deleted, nil
		}

		oldestTable, oldestColumn, found := "", "", false
		var oldestAt time.Time
		for _, t := range retentionTables {
			var ts sql.NullTime
			q := fmt.Sprintf(`SELECT MIN(%s) FROM %s`, t.ageColumn, t.name) //nolint:gosec // t.name/t.ageColumn are from the hardcoded retentionTables list, never user input
			if err := r.db.QueryRowContext(ctx, q).Scan(&ts); err != nil {
				return deleted, fmt.Errorf("%s: %w", t.name, err)
			}
			if !ts.Valid {
				continue
			}
			if !found || ts.Time.Before(oldestAt) {
				oldestTable, oldestColumn, oldestAt, found = t.name, t.ageColumn, ts.Time, true
			}
		}
		if !found {
			// Every table this system can touch is already empty, but
			// we're still over target — nothing left to do; the rest of
			// the size must be coming from something outside this
			// system's scope (or from bloat/indexes not yet reclaimed).
			return deleted, nil
		}

		n, err := r.deleteOldestBatch(ctx, oldestTable, oldestColumn, cfg.DeleteBatchSize, "")
		if err != nil {
			return deleted, fmt.Errorf("%s: %w", oldestTable, err)
		}
		deleted[oldestTable] += n
		if n == 0 {
			return deleted, nil // shouldn't happen given oldestTable was just found non-empty, but avoid ever looping forever
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// deleteOldestBatch deletes up to batchSize of a table's oldest rows
// (by ageColumn), optionally restricted to rows matching extraWhere (a
// pre-built SQL condition using only trusted, hardcoded column
// references — never user input). table/ageColumn come from the
// hardcoded retentionTables list, never from user input, so building
// the query with fmt.Sprintf here is safe.
func (r *Repository) deleteOldestBatch(ctx context.Context, table, ageColumn string, batchSize int, extraWhere string) (int64, error) {
	where := ""
	if extraWhere != "" {
		where = "WHERE " + extraWhere
	}
	query := fmt.Sprintf(
		`DELETE FROM %s WHERE ctid IN (SELECT ctid FROM %s %s ORDER BY %s ASC LIMIT $1)`, //nolint:gosec
		table, table, where, ageColumn,
	)
	res, err := r.db.ExecContext(ctx, query, batchSize)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// retentionTablesSizeGB sums pg_total_relation_size (table + indexes +
// TOAST) across only the tables this system is allowed to prune — never
// the whole database. Scoped deliberately: if something this system
// can't touch (a large system_backups or rule_sets, say) is what's
// actually driving overall database size, that should never trigger
// deleting telemetry/alerts/audit data that isn't the actual problem.
func (r *Repository) retentionTablesSizeGB(ctx context.Context) (float64, error) {
	var totalBytes int64
	for _, t := range retentionTables {
		var bytes int64
		if err := r.db.QueryRowContext(ctx, `SELECT pg_total_relation_size($1)`, t.name).Scan(&bytes); err != nil {
			return 0, fmt.Errorf("%s: %w", t.name, err)
		}
		totalBytes += bytes
	}
	return float64(totalBytes) / (1024 * 1024 * 1024), nil
}
