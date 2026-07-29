package dns

import (
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

const (
	defaultExchangeTimeout = 5 * time.Second
	defaultMaxExchanges    = 5000
)

type exchangeKey struct {
	conversationID string
	transactionID  uint16
	queryName      string
	queryType      uint16
	queryDirection udpconversation.Direction
}

type Tracker struct {
	mu           sync.RWMutex
	timeout      time.Duration
	maxExchanges int
	pending      map[exchangeKey]*DNSExchange
	exchanges    []DNSExchange
	telemetry    Telemetry
	totalRTT     time.Duration
	rttCount     uint64
}

func NewTracker(timeout time.Duration, maxExchanges int) *Tracker {
	if timeout <= 0 {
		timeout = defaultExchangeTimeout
	}
	if maxExchanges <= 0 {
		maxExchanges = defaultMaxExchanges
	}
	return &Tracker{
		timeout:      timeout,
		maxExchanges: maxExchanges,
		pending:      make(map[exchangeKey]*DNSExchange),
	}
}

// Observe consumes one parsed DNS message. A non-nil result is returned for a
// completed response exchange, including orphan responses without a request.
func (t *Tracker) Observe(observation Observation, context udpconversation.ParseContext) *DNSExchange {
	t.mu.Lock()
	defer t.mu.Unlock()

	if observation.IsResponse {
		t.telemetry.DNSResponses++
		switch observation.ResponseCode {
		case 2:
			t.telemetry.DNSSERVFAIL++
		case 3:
			t.telemetry.DNSNXDOMAIN++
		}
		return t.observeResponseLocked(observation, context)
	}

	t.telemetry.DNSQueries++
	key := exchangeKey{
		conversationID: context.ConversationID,
		transactionID:  observation.TransactionID,
		queryName:      observation.QueryName,
		queryType:      observation.QueryType,
		queryDirection: context.Direction,
	}
	if _, retransmission := t.pending[key]; retransmission {
		return nil
	}
	t.makePendingRoomLocked()
	t.pending[key] = &DNSExchange{
		ConversationID: context.ConversationID,
		Direction:      string(context.Direction),
		TransactionID:  observation.TransactionID,
		QueryName:      observation.QueryName,
		QueryType:      observation.QueryType,
		RequestedAt:    observation.Timestamp,
	}
	return nil
}

func (t *Tracker) observeResponseLocked(observation Observation, context udpconversation.ParseContext) *DNSExchange {
	key := exchangeKey{
		conversationID: context.ConversationID,
		transactionID:  observation.TransactionID,
		queryName:      observation.QueryName,
		queryType:      observation.QueryType,
		queryDirection: opposite(context.Direction),
	}
	exchange := t.pending[key]
	if exchange != nil {
		delete(t.pending, key)
		exchange.RespondedAt = observation.Timestamp
		if !observation.Timestamp.Before(exchange.RequestedAt) {
			exchange.RTT = observation.Timestamp.Sub(exchange.RequestedAt)
			t.totalRTT += exchange.RTT
			t.rttCount++
		}
		exchange.ResponseCode = observation.ResponseCode
		exchange.Answers = observation.AnswerCount
		exchange.TTL = observation.TTL
		t.appendLocked(*exchange)
		result := *exchange
		return &result
	}

	// Preserve unmatched responses for diagnostics without inventing an RTT.
	t.telemetry.DNSUnmatchedResponses++
	orphan := DNSExchange{
		ConversationID: context.ConversationID,
		Direction:      string(context.Direction),
		TransactionID:  observation.TransactionID,
		QueryName:      observation.QueryName,
		QueryType:      observation.QueryType,
		RespondedAt:    observation.Timestamp,
		ResponseCode:   observation.ResponseCode,
		Answers:        observation.AnswerCount,
		TTL:            observation.TTL,
	}
	t.appendLocked(orphan)
	return &orphan
}

// Expire marks queries older than the timeout as completed timeouts.
func (t *Tracker) Expire(now time.Time) []DNSExchange {
	t.mu.Lock()
	defer t.mu.Unlock()
	var expired []DNSExchange
	for key, exchange := range t.pending {
		if now.Sub(exchange.RequestedAt) <= t.timeout {
			continue
		}
		delete(t.pending, key)
		exchange.TimedOut = true
		t.telemetry.DNSTimeouts++
		t.appendLocked(*exchange)
		expired = append(expired, *exchange)
	}
	return expired
}

func (t *Tracker) Exchanges() []DNSExchange {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]DNSExchange, len(t.exchanges))
	copy(result, t.exchanges)
	return result
}

func (t *Tracker) Stats() Telemetry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	stats := t.telemetry
	if t.rttCount > 0 {
		stats.DNSAverageRTT = float64(t.totalRTT) / float64(t.rttCount) / float64(time.Millisecond)
	}
	return stats
}

func (t *Tracker) appendLocked(exchange DNSExchange) {
	t.exchanges = append(t.exchanges, exchange)
	if len(t.exchanges) > t.maxExchanges {
		copy(t.exchanges, t.exchanges[len(t.exchanges)-t.maxExchanges:])
		t.exchanges = t.exchanges[:t.maxExchanges]
	}
}

func (t *Tracker) makePendingRoomLocked() {
	if len(t.pending) < t.maxExchanges {
		return
	}
	var oldestKey exchangeKey
	var oldest *DNSExchange
	for key, exchange := range t.pending {
		if oldest == nil || exchange.RequestedAt.Before(oldest.RequestedAt) {
			oldestKey = key
			oldest = exchange
		}
	}
	if oldest != nil {
		delete(t.pending, oldestKey)
		oldest.TimedOut = true
		t.telemetry.DNSTimeouts++
		t.appendLocked(*oldest)
	}
}

func opposite(direction udpconversation.Direction) udpconversation.Direction {
	if direction == udpconversation.DirectionAToB {
		return udpconversation.DirectionBToA
	}
	return udpconversation.DirectionAToB
}
