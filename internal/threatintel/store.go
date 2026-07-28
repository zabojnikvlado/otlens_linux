package threatintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Indicator struct {
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	Provider   string     `json:"provider"`
	ThreatType string     `json:"threat_type,omitempty"`
	Confidence int        `json:"confidence"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}

type Feed struct {
	Name, URL, Path, Format, IndicatorType string
	Confidence                             int
}

type Store struct {
	mu         sync.RWMutex
	indicators map[string]Indicator
	feeds      []Feed
	static     []Indicator
	refresh    time.Duration
	client     *http.Client
}

func New(static []Indicator, feeds []Feed, refresh time.Duration, timeout time.Duration) *Store {
	if refresh <= 0 {
		refresh = time.Hour
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	s := &Store{indicators: map[string]Indicator{}, feeds: feeds, static: static, refresh: refresh, client: &http.Client{Timeout: timeout}}
	s.replace(static)
	return s
}
func key(t, v string) string { return strings.ToLower(strings.TrimSpace(t)) + "|" + normalize(t, v) }
func normalize(t, v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if t == "domain" {
		v = strings.TrimSuffix(v, ".")
	}
	return v
}
func (s *Store) MatchIP(v string) (Indicator, bool) {
	if net.ParseIP(v) == nil {
		return Indicator{}, false
	}
	return s.match("ip", v)
}
func (s *Store) MatchDomain(v string) (Indicator, bool) {
	v = normalize("domain", v)
	for {
		if i, ok := s.match("domain", v); ok {
			return i, true
		}
		idx := strings.IndexByte(v, '.')
		if idx < 0 {
			return Indicator{}, false
		}
		v = v[idx+1:]
	}
}
func (s *Store) match(t, v string) (Indicator, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.indicators[key(t, v)]
	if ok && i.ValidUntil != nil && time.Now().After(*i.ValidUntil) {
		return Indicator{}, false
	}
	return i, ok
}
func (s *Store) ApplySnapshot(items []Indicator) {
	s.replace(items)
}

func (s *Store) replace(items []Indicator) {
	m := map[string]Indicator{}
	for _, i := range items {
		if i.Type == "" || i.Value == "" {
			continue
		}
		if i.Confidence == 0 {
			i.Confidence = 70
		}
		i.Value = normalize(i.Type, i.Value)
		m[key(i.Type, i.Value)] = i
	}
	s.mu.Lock()
	s.indicators = m
	s.mu.Unlock()
}
func (s *Store) Refresh(ctx context.Context) error {
	items := append([]Indicator{}, s.static...)
	var errs []string
	for _, f := range s.feeds {
		xs, err := s.load(ctx, f)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		items = append(items, xs...)
	}
	s.replace(items)
	if len(errs) > 0 {
		return fmt.Errorf("threat feeds: %s", strings.Join(errs, "; "))
	}
	return nil
}
func (s *Store) Run(ctx context.Context) {
	_ = s.Refresh(ctx)
	t := time.NewTicker(s.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Refresh(ctx)
		}
	}
}
func (s *Store) load(ctx context.Context, f Feed) ([]Indicator, error) {
	var r io.ReadCloser
	if f.Path != "" {
		x, e := os.Open(f.Path)
		if e != nil {
			return nil, e
		}
		r = x
	} else {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
		if e != nil {
			return nil, e
		}
		resp, e := s.client.Do(req)
		if e != nil {
			return nil, e
		}
		if resp.StatusCode >= 300 {
			resp.Body.Close()
			return nil, fmt.Errorf("%s returned %s", f.Name, resp.Status)
		}
		r = resp.Body
	}
	defer r.Close()
	provider := f.Name
	if provider == "" {
		provider = "configured-feed"
	}
	confidence := f.Confidence
	if confidence == 0 {
		confidence = 70
	}
	if strings.EqualFold(f.Format, "json") {
		var raw []map[string]interface{}
		if err := json.NewDecoder(r).Decode(&raw); err != nil {
			return nil, err
		}
		out := make([]Indicator, 0, len(raw))
		for _, m := range raw {
			v := fmt.Sprint(m["value"])
			t := fmt.Sprint(m["type"])
			if t == "<nil>" || t == "" {
				t = f.IndicatorType
			}
			if v != "" && v != "<nil>" {
				out = append(out, Indicator{Type: t, Value: v, Provider: provider, ThreatType: fmt.Sprint(m["threat_type"]), Confidence: confidence})
			}
		}
		return out, nil
	}
	sc := bufio.NewScanner(r)
	out := []Indicator{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		v := fields[0]
		t := f.IndicatorType
		if t == "" {
			if net.ParseIP(v) != nil {
				t = "ip"
			} else {
				t = "domain"
			}
		}
		out = append(out, Indicator{Type: t, Value: v, Provider: provider, Confidence: confidence})
	}
	return out, sc.Err()
}
