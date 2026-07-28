package central

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

const threatIntelSchema = `
CREATE TABLE IF NOT EXISTS threat_intel_sources (
 id BIGSERIAL PRIMARY KEY,
 name TEXT NOT NULL,
 source_type TEXT NOT NULL,
 url TEXT NOT NULL DEFAULT '',
 format TEXT NOT NULL DEFAULT 'json',
 indicator_type TEXT NOT NULL DEFAULT '',
 default_confidence INTEGER NOT NULL DEFAULT 70,
 refresh_interval_seconds INTEGER NOT NULL DEFAULT 3600,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 last_sync_at TIMESTAMPTZ,
 last_success_at TIMESTAMPTZ,
 last_error TEXT NOT NULL DEFAULT '',
 accepted_count INTEGER NOT NULL DEFAULT 0,
 rejected_count INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS threat_intel_indicators (
 id BIGSERIAL PRIMARY KEY,
 indicator_type TEXT NOT NULL,
 value TEXT NOT NULL,
 threat_type TEXT NOT NULL DEFAULT '',
 confidence INTEGER NOT NULL DEFAULT 70,
 source_id BIGINT REFERENCES threat_intel_sources(id) ON DELETE CASCADE,
 source_name TEXT NOT NULL DEFAULT '',
 valid_until TIMESTAMPTZ,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(indicator_type,value,source_name)
);
CREATE INDEX IF NOT EXISTS threat_intel_indicator_lookup_idx ON threat_intel_indicators(indicator_type,value) WHERE enabled=TRUE;
CREATE TABLE IF NOT EXISTS threat_intel_state (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
 version BIGINT NOT NULL DEFAULT 1,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO threat_intel_state(singleton,version) VALUES(TRUE,1) ON CONFLICT(singleton) DO NOTHING;
`

type ThreatIntelSource struct {
	ID                     int64      `json:"id"`
	Name                   string     `json:"name"`
	SourceType             string     `json:"source_type"`
	URL                    string     `json:"url"`
	Format                 string     `json:"format"`
	IndicatorType          string     `json:"indicator_type"`
	DefaultConfidence      int        `json:"default_confidence"`
	RefreshIntervalSeconds int        `json:"refresh_interval_seconds"`
	Enabled                bool       `json:"enabled"`
	LastSyncAt             *time.Time `json:"last_sync_at,omitempty"`
	LastSuccessAt          *time.Time `json:"last_success_at,omitempty"`
	LastError              string     `json:"last_error"`
	AcceptedCount          int        `json:"accepted_count"`
	RejectedCount          int        `json:"rejected_count"`
}

type ThreatIntelIndicator struct {
	ID         int64      `json:"id"`
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	ThreatType string     `json:"threat_type"`
	Confidence int        `json:"confidence"`
	SourceID   *int64     `json:"source_id,omitempty"`
	SourceName string     `json:"source_name"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	Enabled    bool       `json:"enabled"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
}

func normalizeTI(t, v string) (string, string, error) {
	t = strings.ToLower(strings.TrimSpace(t))
	v = strings.TrimSpace(strings.ToLower(v))
	if t == "" {
		if net.ParseIP(v) != nil {
			t = "ip"
		} else {
			t = "domain"
		}
	}
	switch t {
	case "ip":
		ip := net.ParseIP(v)
		if ip == nil {
			return "", "", errors.New("invalid IP address")
		}
		v = ip.String()
	case "domain":
		v = strings.TrimSuffix(v, ".")
		if v == "" || !strings.Contains(v, ".") || strings.ContainsAny(v, " /\\") {
			return "", "", errors.New("invalid domain")
		}
	default:
		return "", "", fmt.Errorf("unsupported indicator type %q", t)
	}
	return t, v, nil
}

func (r *Repository) bumpThreatIntelVersion(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `UPDATE threat_intel_state SET version=version+1,updated_at=NOW() WHERE singleton=TRUE`)
	return err
}

func (r *Repository) ListThreatIntelSources(ctx context.Context) ([]ThreatIntelSource, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,source_type,url,format,indicator_type,default_confidence,refresh_interval_seconds,enabled,last_sync_at,last_success_at,last_error,accepted_count,rejected_count FROM threat_intel_sources ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatIntelSource{}
	for rows.Next() {
		var x ThreatIntelSource
		if err := rows.Scan(&x.ID, &x.Name, &x.SourceType, &x.URL, &x.Format, &x.IndicatorType, &x.DefaultConfidence, &x.RefreshIntervalSeconds, &x.Enabled, &x.LastSyncAt, &x.LastSuccessAt, &x.LastError, &x.AcceptedCount, &x.RejectedCount); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *Repository) ListThreatIntelIndicators(ctx context.Context, limit int) ([]ThreatIntelIndicator, error) {
	if limit <= 0 || limit > 100000 {
		limit = 5000
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,indicator_type,value,threat_type,confidence,source_id,source_name,valid_until,enabled,first_seen,last_seen FROM threat_intel_indicators ORDER BY last_seen DESC,id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatIntelIndicator{}
	for rows.Next() {
		var x ThreatIntelIndicator
		if err := rows.Scan(&x.ID, &x.Type, &x.Value, &x.ThreatType, &x.Confidence, &x.SourceID, &x.SourceName, &x.ValidUntil, &x.Enabled, &x.FirstSeen, &x.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *Repository) upsertThreatIntel(ctx context.Context, items []ThreatIntelIndicator, replaceSourceID *int64) (int, int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if replaceSourceID != nil {
		if _, err = tx.ExecContext(ctx, `DELETE FROM threat_intel_indicators WHERE source_id=$1`, *replaceSourceID); err != nil {
			return 0, 0, err
		}
	}
	accepted, rejected := 0, 0
	for _, x := range items {
		t, v, e := normalizeTI(x.Type, x.Value)
		if e != nil {
			rejected++
			continue
		}
		conf := x.Confidence
		if conf <= 0 {
			conf = 70
		}
		if conf > 100 {
			conf = 100
		}
		source := strings.TrimSpace(x.SourceName)
		if source == "" {
			source = "manual"
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO threat_intel_indicators(indicator_type,value,threat_type,confidence,source_id,source_name,valid_until,enabled,first_seen,last_seen,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW(),NOW(),NOW()) ON CONFLICT(indicator_type,value,source_name) DO UPDATE SET threat_type=EXCLUDED.threat_type,confidence=EXCLUDED.confidence,source_id=EXCLUDED.source_id,valid_until=EXCLUDED.valid_until,enabled=EXCLUDED.enabled,last_seen=NOW(),updated_at=NOW()`, t, v, x.ThreatType, conf, x.SourceID, source, x.ValidUntil, x.Enabled)
		if e != nil {
			return accepted, rejected, e
		}
		accepted++
	}
	if _, err = tx.ExecContext(ctx, `UPDATE threat_intel_state SET version=version+1,updated_at=NOW() WHERE singleton=TRUE`); err != nil {
		return accepted, rejected, err
	}
	if err = tx.Commit(); err != nil {
		return accepted, rejected, err
	}
	return accepted, rejected, nil
}

func (r *Repository) ThreatIntelSnapshot(ctx context.Context) (management.ThreatIntelSnapshot, error) {
	var version int64
	if err := r.db.QueryRowContext(ctx, `SELECT version FROM threat_intel_state WHERE singleton=TRUE`).Scan(&version); err != nil {
		return management.ThreatIntelSnapshot{}, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT indicator_type,value,source_name,threat_type,confidence,valid_until FROM threat_intel_indicators WHERE enabled=TRUE AND (valid_until IS NULL OR valid_until>NOW()) ORDER BY indicator_type,value`)
	if err != nil {
		return management.ThreatIntelSnapshot{}, err
	}
	defer rows.Close()
	out := management.ThreatIntelSnapshot{Version: version, GeneratedAt: time.Now().UTC()}
	for rows.Next() {
		var x management.ThreatIntelIndicator
		if err := rows.Scan(&x.Type, &x.Value, &x.Provider, &x.ThreatType, &x.Confidence, &x.ValidUntil); err != nil {
			return out, err
		}
		out.Indicators = append(out.Indicators, x)
	}
	return out, rows.Err()
}

func parseTIJSON(r io.Reader, source string, confidence int) ([]ThreatIntelIndicator, error) {
	var raw []map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(r, 32<<20)).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]ThreatIntelIndicator, 0, len(raw))
	for _, m := range raw {
		c := confidence
		if n, ok := m["confidence"].(float64); ok {
			c = int(n)
		}
		var until *time.Time
		if s := fmt.Sprint(m["valid_until"]); s != "" && s != "<nil>" {
			if t, e := time.Parse(time.RFC3339, s); e == nil {
				until = &t
			}
		}
		out = append(out, ThreatIntelIndicator{Type: fmt.Sprint(m["type"]), Value: fmt.Sprint(m["value"]), ThreatType: fmt.Sprint(m["threat_type"]), Confidence: c, SourceName: source, ValidUntil: until, Enabled: true})
	}
	return out, nil
}
func parseTICSV(r io.Reader, source, defaultType string, confidence int) ([]ThreatIntelIndicator, error) {
	cr := csv.NewReader(io.LimitReader(r, 32<<20))
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	start := 0
	cols := map[string]int{}
	for i, h := range rows[0] {
		cols[strings.ToLower(strings.TrimSpace(h))] = i
	}
	if _, ok := cols["value"]; ok {
		start = 1
	}
	get := func(row []string, name string) string {
		i, ok := cols[name]
		if ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	out := []ThreatIntelIndicator{}
	for _, row := range rows[start:] {
		if len(row) == 0 {
			continue
		}
		v := get(row, "value")
		if v == "" {
			v = row[0]
		}
		t := get(row, "type")
		if t == "" {
			t = defaultType
		}
		c := confidence
		if s := get(row, "confidence"); s != "" {
			if n, e := strconv.Atoi(s); e == nil {
				c = n
			}
		}
		out = append(out, ThreatIntelIndicator{Type: t, Value: v, ThreatType: get(row, "threat_type"), Confidence: c, SourceName: source, Enabled: true})
	}
	return out, nil
}

func (s *Server) listThreatIntelSources(c *gin.Context) {
	v, e := s.Repo.ListThreatIntelSources(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, v)
}
func (s *Server) listThreatIntelIndicators(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "5000"))
	v, e := s.Repo.ListThreatIntelIndicators(c, limit)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, v)
}
func (s *Server) createThreatIntelSource(c *gin.Context) {
	var x ThreatIntelSource
	if c.ShouldBindJSON(&x) != nil || strings.TrimSpace(x.Name) == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	if x.SourceType == "" {
		x.SourceType = "url"
	}
	if x.Format == "" {
		x.Format = "json"
	}
	if x.DefaultConfidence <= 0 {
		x.DefaultConfidence = 70
	}
	if x.RefreshIntervalSeconds <= 0 {
		x.RefreshIntervalSeconds = 3600
	}
	var id int64
	err := s.Repo.db.QueryRowContext(c, `INSERT INTO threat_intel_sources(name,source_type,url,format,indicator_type,default_confidence,refresh_interval_seconds,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, x.Name, x.SourceType, x.URL, x.Format, x.IndicatorType, x.DefaultConfidence, x.RefreshIntervalSeconds, x.Enabled).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	x.ID = id
	c.JSON(201, x)
}
func (s *Server) deleteThreatIntelSource(c *gin.Context) {
	id, e := strconv.ParseInt(c.Param("id"), 10, 64)
	if e != nil {
		c.JSON(400, gin.H{"error": "invalid source id"})
		return
	}
	if _, e = s.Repo.db.ExecContext(c, `DELETE FROM threat_intel_sources WHERE id=$1`, id); e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	_ = s.Repo.bumpThreatIntelVersion(c)
	c.Status(204)
}
func (s *Server) deleteThreatIntelIndicator(c *gin.Context) {
	id, e := strconv.ParseInt(c.Param("id"), 10, 64)
	if e != nil {
		c.JSON(400, gin.H{"error": "invalid indicator id"})
		return
	}
	if _, e = s.Repo.db.ExecContext(c, `DELETE FROM threat_intel_indicators WHERE id=$1`, id); e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	_ = s.Repo.bumpThreatIntelVersion(c)
	c.Status(204)
}
func (s *Server) addThreatIntelIndicator(c *gin.Context) {
	var x ThreatIntelIndicator
	if c.ShouldBindJSON(&x) != nil {
		c.JSON(400, gin.H{"error": "invalid indicator"})
		return
	}
	x.SourceName = "manual"
	x.Enabled = true
	a, r, e := s.Repo.upsertThreatIntel(c, []ThreatIntelIndicator{x}, nil)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	if a == 0 {
		c.JSON(400, gin.H{"error": "indicator rejected"})
		return
	}
	c.JSON(201, gin.H{"accepted": a, "rejected": r})
}
func (s *Server) importThreatIntel(c *gin.Context) {
	f, e := c.FormFile("file")
	if e != nil {
		c.JSON(400, gin.H{"error": "file is required"})
		return
	}
	src := strings.TrimSpace(c.PostForm("source"))
	if src == "" {
		src = f.Filename
	}
	format := strings.ToLower(strings.TrimSpace(c.PostForm("format")))
	if format == "" {
		if strings.HasSuffix(strings.ToLower(f.Filename), ".csv") {
			format = "csv"
		} else {
			format = "json"
		}
	}
	rc, e := f.Open()
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	defer rc.Close()
	var items []ThreatIntelIndicator
	if format == "csv" {
		items, e = parseTICSV(rc, src, c.PostForm("indicator_type"), 70)
	} else {
		items, e = parseTIJSON(rc, src, 70)
	}
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	a, r, e := s.Repo.upsertThreatIntel(c, items, nil)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, gin.H{"accepted": a, "rejected": r})
}

func safeFeedURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return nil, e
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("only http/https feeds are supported")
	}
	host := u.Hostname()
	ips, e := net.LookupIP(host)
	if e != nil {
		return nil, e
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return nil, errors.New("loopback and link-local feed targets are blocked")
		}
	}
	return u, nil
}
func (s *Server) refreshThreatIntelSource(ctx context.Context, id int64) error {
	var x ThreatIntelSource
	if err := s.Repo.db.QueryRowContext(ctx, `SELECT id,name,source_type,url,format,indicator_type,default_confidence,refresh_interval_seconds,enabled,last_sync_at,last_success_at,last_error,accepted_count,rejected_count FROM threat_intel_sources WHERE id=$1`, id).Scan(&x.ID, &x.Name, &x.SourceType, &x.URL, &x.Format, &x.IndicatorType, &x.DefaultConfidence, &x.RefreshIntervalSeconds, &x.Enabled, &x.LastSyncAt, &x.LastSuccessAt, &x.LastError, &x.AcceptedCount, &x.RejectedCount); err != nil {
		return err
	}
	if !x.Enabled {
		return nil
	}
	u, e := safeFeedURL(x.URL)
	if e != nil {
		return e
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		_, e := safeFeedURL(req.URL.String())
		return e
	}}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return e
	}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("feed returned %s", resp.Status)
	}
	var items []ThreatIntelIndicator
	if strings.EqualFold(x.Format, "csv") {
		items, e = parseTICSV(bufio.NewReader(io.LimitReader(resp.Body, 32<<20)), x.Name, x.IndicatorType, x.DefaultConfidence)
	} else {
		items, e = parseTIJSON(io.LimitReader(resp.Body, 32<<20), x.Name, x.DefaultConfidence)
	}
	if e != nil {
		return e
	}
	for i := range items {
		items[i].SourceID = &x.ID
	}
	a, r, e := s.Repo.upsertThreatIntel(ctx, items, &x.ID)
	if e != nil {
		return e
	}
	_, e = s.Repo.db.ExecContext(ctx, `UPDATE threat_intel_sources SET last_sync_at=NOW(),last_success_at=NOW(),last_error='',accepted_count=$2,rejected_count=$3,updated_at=NOW() WHERE id=$1`, x.ID, a, r)
	return e
}
func (s *Server) refreshThreatIntelSourceHTTP(c *gin.Context) {
	id, e := strconv.ParseInt(c.Param("id"), 10, 64)
	if e != nil {
		c.JSON(400, gin.H{"error": "invalid source id"})
		return
	}
	if e = s.refreshThreatIntelSource(c, id); e != nil {
		_, _ = s.Repo.db.ExecContext(c, `UPDATE threat_intel_sources SET last_sync_at=NOW(),last_error=$2 WHERE id=$1`, id, e.Error())
		c.JSON(502, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "refreshed"})
}
func (s *Server) RunThreatIntelFeeds(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, e := s.Repo.db.QueryContext(ctx, `SELECT id FROM threat_intel_sources WHERE enabled=TRUE AND source_type='url' AND (last_sync_at IS NULL OR last_sync_at + (refresh_interval_seconds * INTERVAL '1 second') <= NOW())`)
			if e != nil {
				continue
			}
			ids := []int64{}
			for rows.Next() {
				var id int64
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			for _, id := range ids {
				if e := s.refreshThreatIntelSource(ctx, id); e != nil {
					_, _ = s.Repo.db.ExecContext(ctx, `UPDATE threat_intel_sources SET last_sync_at=NOW(),last_error=$2 WHERE id=$1`, id, e.Error())
				}
			}
		}
	}
}
