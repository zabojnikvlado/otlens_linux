// Package capture reads raw frames off a network interface (via
// gopacket/pcap) and publishes them onto the event bus for
// internal/parser to decode. It's the only package that touches the
// OS packet-capture API — see cmd/tools/interfaces for a standalone
// tool to list what devices are available.
package capture

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

// Engine captures raw frames from a network interface and publishes
// them onto the event bus as core.RawFrame events.
type Engine struct {
	Interface   string
	Snaplen     int32
	Promiscuous bool
	BPFFilter   string

	EventBus *core.EventBus

	handle  *pcap.Handle
	running atomic.Bool

	// closeOnce ensures the handle is closed exactly once per
	// Start() call, regardless of whether Stop() or Start's own
	// cleanup gets there first — calling pcap.Handle.Close() twice
	// is undefined behavior at the libpcap level, not just a no-op.
	// A fresh Once is created each Start() call (see there) since a
	// used-up sync.Once can't be reset for the next run.
	closeOnce *sync.Once
	handleMu  sync.Mutex

	stopRequested atomic.Bool

	packetCount atomic.Uint64
}

// New creates a capture engine for the given interface identifier.
// The identifier can be either the raw OS device name (e.g. "eth0"
// on Linux, "\Device\NPF_{GUID}" on Windows) or the human-friendly
// description shown in config.yaml (e.g. "Ethernet") — it is
// resolved against the available devices when Start is called.
func New(iface string, bus *core.EventBus) *Engine {

	return &Engine{
		Interface:   iface,
		Snaplen:     1600,
		Promiscuous: true,
		EventBus:    bus,
	}
}

// ResolveDevice finds the actual pcap device name for a given
// interface identifier. It tries, in order:
//  1. exact match against the device name (e.g. "eth0" or the full
//     "\Device\NPF_{GUID}")
//  2. exact match against the device description
//  3. case-insensitive substring match against the description
//
// The substring fallback matters most on Windows: Npcap's
// Description is usually the network adapter's hardware name (e.g.
// "Intel(R) Ethernet Connection I219-V"), not the friendly connection
// name shown in Windows' Network Connections panel (e.g.
// "Ethernet") — libpcap has no API to read that friendly name, so an
// exact-match-only lookup would force every Windows user to hunt
// down the raw device name themselves. A substring match on the
// hardware description lets a simple "Ethernet" in config.yaml still
// resolve correctly in the common single-NIC case.
func ResolveDevice(iface string) (string, error) {

	devices, err := pcap.FindAllDevs()

	if err != nil {
		return "", fmt.Errorf("listing capture devices failed: %w", err)
	}

	for _, d := range devices {
		if d.Name == iface {
			return d.Name, nil
		}
	}

	for _, d := range devices {
		if d.Description == iface {
			return d.Name, nil
		}
	}

	// Defensive fallback for a common Windows/YAML mistake: writing
	// "\\Device\\NPF_{GUID}" in config.yaml. In a plain (unquoted)
	// YAML scalar, backslashes are not escape characters, so that
	// literally becomes a double-backslash string that won't match
	// any real device name — collapse repeated backslashes and try
	// again before giving up.
	if normalized := collapseBackslashes(iface); normalized != iface {

		for _, d := range devices {
			if d.Name == normalized {
				return d.Name, nil
			}
		}
	}

	target := strings.ToLower(iface)

	var substringMatches []pcap.Interface

	for _, d := range devices {
		if strings.Contains(strings.ToLower(d.Description), target) {
			substringMatches = append(substringMatches, d)
		}
	}

	if len(substringMatches) == 1 {
		return substringMatches[0].Name, nil
	}

	if len(substringMatches) > 1 {

		return "", fmt.Errorf(
			"capture interface %q matches multiple devices, use the exact device name instead:\n%s",
			iface,
			formatDeviceList(substringMatches),
		)
	}

	return "", fmt.Errorf(
		"capture interface %q not found; available devices:\n%s",
		iface,
		formatDeviceList(devices),
	)
}

// collapseBackslashes replaces any run of 2+ backslashes with a
// single one, e.g. "\\\\Device\\\\NPF_{GUID}" -> "\Device\NPF_{GUID}".
func collapseBackslashes(s string) string {

	for strings.Contains(s, `\\`) {
		s = strings.ReplaceAll(s, `\\`, `\`)
	}

	return s
}

// formatDeviceList renders devices as "Name — Description" lines, one
// per device, so a failed lookup tells the user exactly what values
// are valid for configs/sensor.config.example.yaml's capture.interface — or can be
// obtained by running cmd/tools/interfaces.
func formatDeviceList(devices []pcap.Interface) string {

	var b strings.Builder

	for _, d := range devices {

		description := d.Description

		if description == "" {
			description = "(no description)"
		}

		fmt.Fprintf(&b, "  %s — %s\n", d.Name, description)
	}

	return b.String()
}

// Start opens the capture device and blocks, publishing each
// captured frame to the event bus until Stop is called. It returns
// an error instead of terminating the process, so the caller decides
// how to react to capture failures. Safe to call again after a
// Stop() — e.g. the admin API's start/stop capture control.
func (e *Engine) Start() error {

	if !e.running.CompareAndSwap(false, true) {
		return fmt.Errorf("capture already running")
	}

	e.stopRequested.Store(false)

	defer e.running.Store(false)

	device, err := ResolveDevice(e.Interface)

	if err != nil {
		return err
	}

	snaplen := e.Snaplen

	if snaplen <= 0 {
		snaplen = 1600
	}

	// A short read timeout (rather than pcap.BlockForever) is what
	// makes Stop() actually responsive: closing the handle from
	// another goroutine while this one is blocked inside a native
	// pcap read call doesn't reliably interrupt that call on every
	// platform/Npcap version — it can end up waiting for the next
	// packet to arrive (or, on a quiet link, effectively never
	// return) before noticing the handle is gone. Waking up on our
	// own every second to check stopRequested, instead of depending
	// on that interrupt, is what actually guarantees Stop() takes
	// effect promptly regardless of platform quirks.
	handle, err := pcap.OpenLive(
		device,
		snaplen,
		e.Promiscuous,
		time.Second,
	)

	if err != nil {
		return fmt.Errorf("opening capture device %q failed: %w", device, err)
	}

	if e.BPFFilter != "" {

		if err := handle.SetBPFFilter(e.BPFFilter); err != nil {
			handle.Close()
			return fmt.Errorf("invalid BPF filter %q: %w", e.BPFFilter, err)
		}
	}

	e.handleMu.Lock()
	e.handle = handle
	e.closeOnce = &sync.Once{}
	closeOnce := e.closeOnce
	e.handleMu.Unlock()

	defer closeOnce.Do(handle.Close)

	logger.Log.Info(
		"Capture started",
		zap.String("interface", e.Interface),
		zap.String("device", device),
		zap.Int32("snaplen", snaplen),
		zap.Bool("promiscuous", e.Promiscuous),
		zap.String("bpf_filter", e.BPFFilter),
	)

	stopStats := e.logStatsPeriodically(10 * time.Second)
	defer close(stopStats)

	for !e.stopRequested.Load() {

		data, ci, err := handle.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired {
			// Just the periodic wakeup with no packet available —
			// loop back around to re-check stopRequested.
			continue
		}

		if err != nil {
			// A real read error (e.g. the handle was closed out from
			// under us) — nothing more to do.
			return nil
		}

		e.process(data, ci.Timestamp, false)
	}

	return nil
}

// Stop requests that the capture loop in Start exit at its next
// wakeup (at most ~1 second later — see Start's doc comment on why a
// short read timeout is used instead of relying on closing the
// handle to interrupt an in-progress read) and closes the handle.
// Safe to call even if not currently running.
func (e *Engine) Stop() {

	e.stopRequested.Store(true)

	e.handleMu.Lock()
	handle := e.handle
	closeOnce := e.closeOnce
	e.handleMu.Unlock()

	if handle != nil && closeOnce != nil {
		closeOnce.Do(handle.Close)
	}
}

// StopAndWait stops the active capture session and waits until Start has
// completely released its running flag. Stop itself is intentionally
// asynchronous, so callers that immediately start a new session (notably the
// PCAP analysis workflow) must use this helper to avoid racing the old Start
// goroutine and receiving "capture already running".
func (e *Engine) StopAndWait(timeout time.Duration) error {
	e.Stop()

	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	deadline := time.Now().Add(timeout)
	for e.IsRunning() {
		if time.Now().After(deadline) {
			return fmt.Errorf("capture did not stop within %s", timeout)
		}
		time.Sleep(25 * time.Millisecond)
	}

	return nil
}

// IsRunning reports whether a capture session is currently active.
func (e *Engine) IsRunning() bool {
	return e.running.Load()
}

// process publishes one captured frame, tagged with its actual
// capture timestamp (from pcap's own CaptureInfo — live capture and
// AnalyzeFile both funnel through here with their respective
// timestamp source) rather than time.Now(), and whether it came from
// a manual pcap analysis rather than live capture — see
// core.RawFrame's doc comment for why both distinctions matter.
func (e *Engine) process(data []byte, timestamp time.Time, fromAnalysis bool) {

	e.packetCount.Add(1)

	e.EventBus.Publish(
		core.Event{
			Type: core.EventPacketCaptured,
			Data: core.RawFrame{
				Data:         append([]byte(nil), data...),
				Timestamp:    timestamp,
				FromAnalysis: fromAnalysis,
			},
		},
	)
}

// logStatsPeriodically logs a packet count summary on an interval
// instead of logging every single captured packet, which would
// otherwise flood the logs on a busy interface. Call close() on the
// returned channel to stop the ticker goroutine.
func (e *Engine) logStatsPeriodically(interval time.Duration) chan struct{} {

	stop := make(chan struct{})

	go func() {

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var last uint64

		for {
			select {
			case <-ticker.C:

				total := e.packetCount.Load()

				logger.Log.Info(
					"Capture stats",
					zap.Uint64("total_packets", total),
					zap.Uint64("packets_since_last", total-last),
				)

				last = total

			case <-stop:
				return
			}
		}
	}()

	return stop
}
