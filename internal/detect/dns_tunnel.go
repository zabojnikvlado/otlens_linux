package detect

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	passivedns "github.com/zabojnikvlado/otlens_linux/internal/dns"
)

func (e *Engine) startDNSTunnelWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventDNSObservation)
	go func() {
		for ev := range ch {
			if o, ok := ev.Data.(passivedns.Observation); ok {
				e.handleDNSTunnel(o)
			}
		}
	}()
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range strings.ToLower(s) {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

func longestDNSLabel(name string) string {
	best := ""
	for _, x := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(x) > len(best) {
			best = x
		}
	}
	return best
}

func (e *Engine) handleDNSTunnel(o passivedns.Observation) {
	if o.ClientIP == "" || o.QueryName == "" {
		return
	}
	now := o.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	name := strings.ToLower(strings.TrimSuffix(o.QueryName, "."))
	e.policyMutex.Lock()
	st := e.dnsTunnel[o.ClientIP]
	if st == nil {
		st = &dnsTunnelState{}
		e.dnsTunnel[o.ClientIP] = st
	}
	window := time.Duration(e.builtinParameter("builtin.dns_tunneling", "window_seconds", 600)) * time.Second
	if window <= 0 {
		window = 10 * time.Minute
	}
	minQueries := int(e.builtinParameter("builtin.dns_tunneling", "min_queries", 20))
	if minQueries < 1 {
		minQueries = 1
	}
	scoreThreshold := int(e.builtinParameter("builtin.dns_tunneling", "score_threshold", 60))
	if scoreThreshold < 1 {
		scoreThreshold = 1
	}
	cut := now.Add(-window)
	if o.IsResponse {
		st.Responses = append(st.Responses, dnsTunnelResponseSample{At: now, Bytes: o.PayloadBytes})
	} else {
		st.Samples = append(st.Samples, dnsTunnelSample{At: now, Name: name, QueryType: o.QueryType, QueryBytes: o.PayloadBytes})
	}
	j := 0
	for _, x := range st.Samples {
		if !x.At.Before(cut) {
			st.Samples[j] = x
			j++
		}
	}
	st.Samples = st.Samples[:j]
	j = 0
	for _, x := range st.Responses {
		if !x.At.Before(cut) {
			st.Responses[j] = x
			j++
		}
	}
	st.Responses = st.Responses[:j]
	if len(st.Samples) > 2000 {
		st.Samples = st.Samples[len(st.Samples)-2000:]
	}
	if len(st.Responses) > 2000 {
		st.Responses = st.Responses[len(st.Responses)-2000:]
	}
	samples := append([]dnsTunnelSample(nil), st.Samples...)
	responses := append([]dnsTunnelResponseSample(nil), st.Responses...)
	e.policyMutex.Unlock()
	if o.IsResponse || len(samples) < minQueries {
		return
	}

	unique := map[string]bool{}
	txt, long, highEntropy, totalLen, queryBytes := 0, 0, 0, 0, 0
	maxEntropy := 0.0
	for _, x := range samples {
		unique[x.Name] = true
		totalLen += len(x.Name)
		queryBytes += x.QueryBytes
		if x.QueryType == 16 {
			txt++
		}
		label := longestDNSLabel(x.Name)
		ent := shannonEntropy(label)
		if ent > maxEntropy {
			maxEntropy = ent
		}
		if len(label) >= 35 {
			long++
		}
		if len(label) >= 20 && ent >= 3.8 {
			highEntropy++
		}
	}
	score := 0
	signals := []string{}
	ratio := func(n int) float64 { return float64(n) / float64(len(samples)) }
	if len(unique) >= 20 {
		score += 20
		signals = append(signals, "many_unique_names")
	}
	if ratio(long) >= 0.30 {
		score += 20
		signals = append(signals, "long_labels")
	}
	if ratio(highEntropy) >= 0.25 {
		score += 30
		signals = append(signals, "high_entropy_labels")
	}
	if ratio(txt) >= 0.30 {
		score += 20
		signals = append(signals, "txt_heavy")
	}
	avg := float64(totalLen) / float64(len(samples))
	if avg >= 45 {
		score += 15
		signals = append(signals, "long_average_query")
	}
	responseBytes := 0
	for _, x := range responses {
		responseBytes += x.Bytes
	}
	avgQueryBytes := 0.0
	if len(samples) > 0 {
		avgQueryBytes = float64(queryBytes) / float64(len(samples))
	}
	if avgQueryBytes >= 80 {
		score += 15
		signals = append(signals, "large_query_payloads")
	}
	if queryBytes >= 4096 && (responseBytes == 0 || queryBytes > responseBytes*2) {
		score += 15
		signals = append(signals, "upstream_byte_asymmetry")
	}
	if responseBytes >= 8192 && queryBytes > 0 && responseBytes > queryBytes*4 && ratio(txt) >= 0.20 {
		score += 10
		signals = append(signals, "txt_response_asymmetry")
	}
	if score < scoreThreshold || e.behaviorDetectionsSuppressed() {
		return
	}
	if score > 100 {
		score = 100
	}
	evidence := map[string]interface{}{"queries_window": len(samples), "responses_window": len(responses), "window_seconds": window.Seconds(), "score_threshold": scoreThreshold, "query_bytes_10m": queryBytes, "response_bytes_10m": responseBytes, "average_query_payload_bytes": avgQueryBytes, "unique_names": len(unique), "txt_ratio": ratio(txt), "long_label_ratio": ratio(long), "high_entropy_ratio": ratio(highEntropy), "max_label_entropy": maxEntropy, "average_query_length": avg, "signals": signals, "score": score, "latest_query": name}
	e.raiseBuiltinAlert("builtin.dns_tunneling", AlertDNSTunneling, "high", "dns-tunnel|"+o.ClientIP,
		fmt.Sprintf("Possible DNS tunneling from %s (score %d): %s", o.ClientIP, score, strings.Join(signals, ", ")), o.ClientIP, evidence, now, window)
}
