package central

import (
	"context"
	"time"
)

// DayCount is one point on a daily trend line.
type DayCount struct {
	Day   time.Time
	Count int
}

// AlertsByDay returns the number of *newly first-seen* alerts per day
// over the last `days` days — a day where nothing new happened simply
// doesn't appear in the result (the caller fills gaps with zero if it
// wants a continuous line). Based on alert_history.first_seen, so an
// alert whose Count keeps climbing on an old, still-active finding
// doesn't inflate a later day's count — only the day it first appeared
// does.
func (r *Repository) AlertsByDay(ctx context.Context, days int) ([]DayCount, error) {
	if days <= 0 {
		days = 30
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT date_trunc('day', first_seen) AS day, COUNT(*)
		FROM alert_history
		WHERE first_seen > NOW() - ($1 * INTERVAL '1 day')
		GROUP BY day ORDER BY day ASC`,
		days,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDayCounts(rows)
}

// NewAssetsByDay returns the number of distinct new (sensor, MAC)
// assets first observed per day over the last `days` days — based on
// topology_nodes.first_seen. A device that changed IP shows up once,
// on the day its *earliest* recorded IP first appeared, not once per
// IP it's ever had (topology_nodes has one row per (sensor, ip), so
// this counts DISTINCT (sensor_id, mac) rather than raw rows).
func (r *Repository) NewAssetsByDay(ctx context.Context, days int) ([]DayCount, error) {
	if days <= 0 {
		days = 30
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT day, COUNT(*) FROM (
			SELECT sensor_id, mac, MIN(date_trunc('day', first_seen)) AS day
			FROM topology_nodes
			WHERE mac != ''
			GROUP BY sensor_id, mac
		) AS first_per_asset
		WHERE day > NOW() - ($1 * INTERVAL '1 day')
		GROUP BY day ORDER BY day ASC`,
		days,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDayCounts(rows)
}

func scanDayCounts(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
}) ([]DayCount, error) {
	out := make([]DayCount, 0)
	for rows.Next() {
		var d DayCount
		if err := rows.Scan(&d.Day, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
