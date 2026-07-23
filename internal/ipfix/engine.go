package ipfix

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

// maxDatagramSize is generously large — IPFIX messages are sent one
// per UDP datagram and typically well under 1500 bytes (path MTU),
// but some exporters batch many Data Records into one larger
// message; this comfortably covers that without risking truncation.
const maxDatagramSize = 65535

// maxConsecutiveReadErrors bounds how many read errors in a row
// Start tolerates before giving up entirely — see the doc comment
// on the read loop below for why a single error, or even a handful,
// shouldn't kill the whole collector.
const maxConsecutiveReadErrors = 20

// Engine listens for IPFIX export packets over UDP and publishes each
// decoded FlowRecord as core.EventIPFIXFlow. See the package doc
// comment for what this can and can't see compared to live packet
// capture.
type Engine struct {
	ListenAddr string

	EventBus *core.EventBus

	conn    *net.UDPConn
	store   *templateStore
	running atomic.Bool

	// stopping distinguishes Stop() intentionally closing conn (read
	// loop should exit quietly) from any other read error (should be
	// logged and retried, not silently swallowed) — see Start's read
	// loop.
	stopping atomic.Bool
}

func New(listenAddr string, bus *core.EventBus) *Engine {

	return &Engine{
		ListenAddr: listenAddr,
		EventBus:   bus,
		store:      newTemplateStore(),
	}
}

// Start opens the UDP listener and blocks, decoding and publishing
// flow records until Stop is called. Like capture.Engine.Start, it
// returns an error instead of terminating the process, and is safe
// to call again after a Stop() — e.g. the admin API's start/stop
// capture control, which works the same way in ipfix mode as it
// does for live npcap capture.
func (e *Engine) Start() error {

	if !e.running.CompareAndSwap(false, true) {
		return fmt.Errorf("ipfix collector already running")
	}

	defer e.running.Store(false)

	e.stopping.Store(false)

	addr, err := net.ResolveUDPAddr("udp", e.ListenAddr)

	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)

	if err != nil {
		return err
	}

	e.conn = conn

	logger.Log.Info(
		"IPFIX collector listening",
		zap.String("addr", e.ListenAddr),
	)

	buf := make([]byte, maxDatagramSize)
	consecutiveErrors := 0

	for {

		n, _, err := conn.ReadFromUDP(buf)

		if err != nil {

			if e.stopping.Load() {
				// Expected — Stop() closed the connection on purpose.
				return nil
			}

			// A genuine, unexpected read error — not the same thing
			// as being told to stop. Windows UDP sockets in
			// particular have a well-known quirk (WSAECONNRESET)
			// where a single unrelated packet — an ICMP "port
			// unreachable" response to something this socket sent
			// earlier, or sometimes just a malformed/unexpected
			// inbound datagram — fails the *next* read even though
			// the socket itself is still perfectly usable. Treating
			// every read error as "time to shut down" (the previous
			// behavior here) meant one blip like that silently
			// killed the whole collector with zero trace in the
			// log — the rest of the application kept running fine,
			// so nothing else would ever indicate IPFIX had stopped
			// receiving data. Logging and retrying is far more
			// robust; maxConsecutiveReadErrors is the safety net
			// against spinning forever on a socket that's genuinely,
			// persistently broken.
			consecutiveErrors++

			logger.Log.Warn(
				"IPFIX read error — retrying",
				zap.Error(err),
				zap.Int("consecutive_errors", consecutiveErrors),
			)

			if consecutiveErrors >= maxConsecutiveReadErrors {
				return fmt.Errorf("too many consecutive IPFIX read errors, last: %w", err)
			}

			// Brief backoff so a persistently failing socket doesn't
			// spin this loop at full CPU between now and hitting the
			// limit above.
			time.Sleep(100 * time.Millisecond)

			continue
		}

		consecutiveErrors = 0

		records, err := DecodeMessage(buf[:n], e.store)

		if err != nil {

			logger.Log.Warn(
				"Discarding malformed IPFIX message",
				zap.Error(err),
			)

			continue
		}

		for _, record := range records {

			e.EventBus.Publish(
				core.Event{
					Type: core.EventIPFIXFlow,
					Data: record,
				},
			)
		}
	}
}

// Stop closes the UDP listener, causing Start's read loop to return.
// Safe to call even if not currently running — net.UDPConn.Close()
// is safe to call more than once (a second call just returns a
// harmless "already closed" error, unlike pcap.Handle.Close() in
// internal/capture, which needs its own explicit guard against that).
func (e *Engine) Stop() {

	e.stopping.Store(true)

	if e.conn != nil {
		e.conn.Close()
	}
}

// IsRunning reports whether the collector is currently active.
func (e *Engine) IsRunning() bool {
	return e.running.Load()
}
