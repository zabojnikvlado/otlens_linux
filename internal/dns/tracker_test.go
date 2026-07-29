package dns

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

func dnsContext(conversation string, direction udpconversation.Direction) udpconversation.ParseContext {
	return udpconversation.ParseContext{ConversationID: conversation, Direction: direction}
}

func query(id uint16, name string, queryType uint16, at time.Time) Observation {
	return Observation{
		Timestamp: at, TransactionID: id, QueryName: name, QueryType: queryType,
	}
}

func response(id uint16, name string, queryType uint16, code uint8, answers int, at time.Time) Observation {
	observation := Observation{
		Timestamp: at, TransactionID: id, QueryName: name, QueryType: queryType,
		ResponseCode: code, IsResponse: true, AnswerCount: answers,
	}
	for range answers {
		observation.Answers = append(observation.Answers, "192.0.2.1")
	}
	return observation
}

func TestAAndAAAAQueryResponse(t *testing.T) {
	for _, test := range []struct {
		name      string
		queryType uint16
	}{
		{name: "A", queryType: 1},
		{name: "AAAA", queryType: 28},
	} {
		t.Run(test.name, func(t *testing.T) {
			tracker := NewTracker(time.Second, 10)
			now := time.Unix(10_000, 0)
			tracker.Observe(query(7, "example.test", test.queryType, now), dnsContext("conversation-1", udpconversation.DirectionAToB))
			exchange := tracker.Observe(response(7, "example.test", test.queryType, 0, 1, now.Add(20*time.Millisecond)), dnsContext("conversation-1", udpconversation.DirectionBToA))

			if exchange == nil || exchange.QueryType != test.queryType || exchange.RTT != 20*time.Millisecond ||
				exchange.Answers != 1 || exchange.TimedOut {
				t.Fatalf("unexpected exchange: %#v", exchange)
			}
		})
	}
}

func TestNXDOMAINAndSERVFAILTelemetry(t *testing.T) {
	tracker := NewTracker(time.Second, 10)
	now := time.Unix(20_000, 0)
	for index, code := range []uint8{3, 2} {
		id := uint16(index + 1)
		name := []string{"missing.test", "broken.test"}[index]
		tracker.Observe(query(id, name, 1, now), dnsContext("conversation-1", udpconversation.DirectionAToB))
		exchange := tracker.Observe(response(id, name, 1, code, 0, now.Add(time.Duration(index+1)*time.Millisecond)), dnsContext("conversation-1", udpconversation.DirectionBToA))
		if exchange == nil || exchange.ResponseCode != code {
			t.Fatalf("response code was not attached: %#v", exchange)
		}
	}
	stats := tracker.Stats()
	if stats.DNSNXDOMAIN != 1 || stats.DNSSERVFAIL != 1 {
		t.Fatalf("unexpected telemetry: %#v", stats)
	}
}

func TestResponseWithoutRequest(t *testing.T) {
	tracker := NewTracker(time.Second, 10)
	now := time.Unix(30_000, 0)
	exchange := tracker.Observe(response(9, "orphan.test", 1, 0, 1, now), dnsContext("conversation-1", udpconversation.DirectionBToA))

	if exchange == nil || !exchange.RequestedAt.IsZero() || exchange.RespondedAt != now || exchange.RTT != 0 {
		t.Fatalf("unexpected orphan response: %#v", exchange)
	}
	if tracker.Stats().DNSResponses != 1 {
		t.Fatalf("unexpected telemetry: %#v", tracker.Stats())
	}
}

func TestRequestWithoutResponseTimesOut(t *testing.T) {
	tracker := NewTracker(100*time.Millisecond, 10)
	now := time.Unix(40_000, 0)
	tracker.Observe(query(10, "timeout.test", 1, now), dnsContext("conversation-1", udpconversation.DirectionAToB))

	expired := tracker.Expire(now.Add(100*time.Millisecond + time.Nanosecond))
	if len(expired) != 1 || !expired[0].TimedOut || !expired[0].RespondedAt.IsZero() {
		t.Fatalf("unexpected timeout: %#v", expired)
	}
	if tracker.Stats().DNSTimeouts != 1 {
		t.Fatalf("unexpected telemetry: %#v", tracker.Stats())
	}
}

func TestSameTransactionIDInDifferentConversations(t *testing.T) {
	tracker := NewTracker(time.Second, 10)
	now := time.Unix(50_000, 0)
	for _, conversation := range []string{"conversation-1", "conversation-2"} {
		tracker.Observe(query(11, "same.test", 1, now), dnsContext(conversation, udpconversation.DirectionAToB))
	}
	second := tracker.Observe(response(11, "same.test", 1, 0, 1, now.Add(10*time.Millisecond)), dnsContext("conversation-2", udpconversation.DirectionBToA))
	first := tracker.Observe(response(11, "same.test", 1, 0, 1, now.Add(20*time.Millisecond)), dnsContext("conversation-1", udpconversation.DirectionBToA))

	if first.ConversationID != "conversation-1" || first.RTT != 20*time.Millisecond ||
		second.ConversationID != "conversation-2" || second.RTT != 10*time.Millisecond {
		t.Fatalf("cross-conversation pairing: first=%#v second=%#v", first, second)
	}
}

func TestMultipleParallelQueries(t *testing.T) {
	tracker := NewTracker(time.Second, 10)
	now := time.Unix(60_000, 0)
	context := dnsContext("conversation-1", udpconversation.DirectionAToB)
	responseContext := dnsContext("conversation-1", udpconversation.DirectionBToA)
	tracker.Observe(query(12, "one.test", 1, now), context)
	tracker.Observe(query(13, "two.test", 28, now.Add(time.Millisecond)), context)

	second := tracker.Observe(response(13, "two.test", 28, 0, 1, now.Add(5*time.Millisecond)), responseContext)
	first := tracker.Observe(response(12, "one.test", 1, 0, 1, now.Add(8*time.Millisecond)), responseContext)
	if second.QueryName != "two.test" || second.QueryType != 28 ||
		first.QueryName != "one.test" || first.QueryType != 1 {
		t.Fatalf("parallel queries paired incorrectly: first=%#v second=%#v", first, second)
	}
}

func TestQueryRetransmissionKeepsOriginalRequest(t *testing.T) {
	tracker := NewTracker(time.Second, 10)
	now := time.Unix(70_000, 0)
	context := dnsContext("conversation-1", udpconversation.DirectionAToB)
	tracker.Observe(query(14, "retry.test", 1, now), context)
	tracker.Observe(query(14, "retry.test", 1, now.Add(50*time.Millisecond)), context)
	exchange := tracker.Observe(response(14, "retry.test", 1, 0, 1, now.Add(80*time.Millisecond)), dnsContext("conversation-1", udpconversation.DirectionBToA))

	if exchange.RequestedAt != now || exchange.RTT != 80*time.Millisecond || len(tracker.Exchanges()) != 1 {
		t.Fatalf("retransmission created/replaced exchange: %#v", exchange)
	}
	if tracker.Stats().DNSQueries != 2 {
		t.Fatalf("query packet telemetry = %#v", tracker.Stats())
	}
}

func TestDelayedResponseAfterTimeoutIsOrphan(t *testing.T) {
	tracker := NewTracker(100*time.Millisecond, 10)
	now := time.Unix(80_000, 0)
	tracker.Observe(query(15, "late.test", 1, now), dnsContext("conversation-1", udpconversation.DirectionAToB))
	tracker.Expire(now.Add(200 * time.Millisecond))
	responseExchange := tracker.Observe(response(15, "late.test", 1, 0, 1, now.Add(250*time.Millisecond)), dnsContext("conversation-1", udpconversation.DirectionBToA))

	exchanges := tracker.Exchanges()
	if len(exchanges) != 2 || !exchanges[0].TimedOut ||
		!responseExchange.RequestedAt.IsZero() || responseExchange.RTT != 0 {
		t.Fatalf("late response incorrectly paired: %#v", exchanges)
	}
}

func TestAverageRTTTelemetry(t *testing.T) {
	tracker := NewTracker(time.Second, 10)
	now := time.Unix(90_000, 0)
	for index, rtt := range []time.Duration{10 * time.Millisecond, 30 * time.Millisecond} {
		id := uint16(index + 20)
		name := []string{"average-one.test", "average-two.test"}[index]
		tracker.Observe(query(id, name, 1, now), dnsContext("conversation-1", udpconversation.DirectionAToB))
		tracker.Observe(response(id, name, 1, 0, 1, now.Add(rtt)), dnsContext("conversation-1", udpconversation.DirectionBToA))
	}
	stats := tracker.Stats()
	if stats.DNSQueries != 2 || stats.DNSResponses != 2 || stats.DNSAverageRTT != 20 {
		t.Fatalf("unexpected telemetry: %#v", stats)
	}
}
