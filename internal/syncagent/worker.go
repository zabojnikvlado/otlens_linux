package syncagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/flow"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"github.com/zabojnikvlado/otlens_linux/internal/threatintel"
)

type Worker struct {
	Client          *Client
	Detect          *detect.Engine
	Flow            *flow.Engine
	Uptime          func() int64
	Health          func() map[string]string
	Metrics         func() map[string]interface{}
	Versions        func() map[string]string
	CaptureInfo     func() map[string]interface{}
	Snapshot        func() (management.TelemetrySnapshot, error)
	ApplyCommand    func(management.Command)
	ProcessAnalysis func(context.Context)
	ThreatIntel     *threatintel.Store

	mu              sync.Mutex
	lastAttempt     time.Time
	lastSuccess     time.Time
	lastDataSent    time.Time
	lastError       string
	failures        int
	sequence        int64
	pending         int64
	analysisMu      sync.Mutex
	analysisRunning bool
	registered      bool
}

func (w *Worker) syncHealth() management.SyncHealth {
	w.mu.Lock()
	defer w.mu.Unlock()
	return management.SyncHealth{LastAttemptAt: w.lastAttempt, LastSuccessAt: w.lastSuccess, LastDataSentAt: w.lastDataSent, PendingRecords: w.pending, ConsecutiveFailures: w.failures, LastError: w.lastError, Sequence: w.sequence}
}

func (w *Worker) markAttempt() { w.mu.Lock(); w.lastAttempt = time.Now().UTC(); w.mu.Unlock() }
func (w *Worker) markFailure(err error) {
	w.mu.Lock()
	w.failures++
	w.lastError = err.Error()
	w.mu.Unlock()
}
func (w *Worker) markSuccess(sequence int64) {
	w.mu.Lock()
	w.failures = 0
	w.lastError = ""
	w.lastSuccess = time.Now().UTC()
	w.lastDataSent = w.lastSuccess
	w.sequence = sequence
	w.pending = 0
	w.mu.Unlock()
}

func (w *Worker) Run(ctx context.Context) {
	// A persisted per-sensor credential means this process has already been
	// enrolled. On a normal restart use that credential directly instead of
	// POSTing /register again: registration is an enrollment/recovery operation,
	// not a liveness signal. If Central later rejects the credential (for
	// example after its database was rebuilt), the first authenticated 401 marks
	// the worker unregistered and the next cycle runs the re-enrollment flow.
	if w.Client.HasSensorCredential() {
		w.mu.Lock()
		w.registered = true
		w.mu.Unlock()
	}

	ticker := time.NewTicker(w.Client.cfg.Interval)
	defer ticker.Stop()

	w.sync(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sync(ctx)
		}
	}
}

func (w *Worker) ensureRegistered(ctx context.Context) error {
	w.mu.Lock()
	registered := w.registered
	w.mu.Unlock()
	if registered {
		return nil
	}
	if err := w.Client.Register(ctx); err != nil {
		return err
	}
	w.mu.Lock()
	w.registered = true
	w.mu.Unlock()
	return nil
}

func (w *Worker) markUnregistered() {
	w.mu.Lock()
	w.registered = false
	w.mu.Unlock()
}

func (w *Worker) sync(ctx context.Context) {
	if err := w.ensureRegistered(ctx); err != nil {
		log.Printf("OTLens Central registration failed: %v", err)
		return
	}

	commands, err := w.Client.PullRules(ctx, func(rules []*detect.Rule) error { w.Detect.ReplaceManagedRules(rules); return nil }, func(snapshot management.ThreatIntelSnapshot) error {
		if w.ThreatIntel == nil {
			return nil
		}
		items := make([]threatintel.Indicator, 0, len(snapshot.Indicators))
		for _, indicator := range snapshot.Indicators {
			items = append(items, threatintel.Indicator{Type: indicator.Type, Value: indicator.Value, Provider: indicator.Provider, ThreatType: indicator.ThreatType, Confidence: indicator.Confidence, ValidUntil: indicator.ValidUntil})
		}
		w.ThreatIntel.ApplySnapshot(items)
		return nil
	}, func(contexts []management.AssetPolicyContext) error {
		if w.Detect == nil {
			return nil
		}
		converted := make([]detect.AssetPolicyContext, 0, len(contexts))
		for _, x := range contexts {
			converted = append(converted, detect.AssetPolicyContext{IP: x.AssetIP, Role: x.AssetRole, Criticality: x.Criticality, Zone: x.Zone, PurdueLevel: x.PurdueOverride})
		}
		w.Detect.SetAssetPolicyContexts(converted)
		return nil
	}, func(seg management.SegmentationConfig) error {
		if w.Detect != nil {
			if seg.Managed {
				w.Detect.UpdateSegmentationConfig(seg.VLANLevels, seg.MaxLevelJump)
			} else {
				w.Detect.RestoreLocalSegmentationConfig()
			}
		}
		return nil
	})
	if err != nil {
		if IsSensorAuthError(err) {
			w.markUnregistered()
			log.Printf("OTLens Central sensor credential is no longer accepted; re-enrollment will be attempted: %v", err)
			return
		}
		log.Printf("OTLens Central rule synchronization failed: %v", err)
	} else if w.ApplyCommand != nil {
		for _, command := range commands {
			w.ApplyCommand(command)
		}
	}

	h := management.Heartbeat{SensorID: w.Client.cfg.SensorID, Version: w.Client.cfg.Version, Hostname: w.Client.cfg.Hostname, Sync: w.syncHealth()}
	if w.Uptime != nil {
		h.Uptime = w.Uptime()
	}
	if w.Health != nil {
		h.Health = w.Health()
	}
	if w.Metrics != nil {
		h.Metrics = w.Metrics()
	}
	if w.Versions != nil {
		h.Versions = w.Versions()
	}
	if w.CaptureInfo != nil {
		h.Capture = w.CaptureInfo()
	}
	if err := w.Client.Heartbeat(ctx, h); err != nil {
		if IsSensorAuthError(err) {
			w.markUnregistered()
			log.Printf("OTLens Central sensor credential is no longer accepted; re-enrollment will be attempted: %v", err)
			return
		}
		log.Printf("OTLens Central heartbeat failed: %v", err)
	}

	if w.Snapshot != nil {
		snapshotStarted := time.Now()
		snapshot, err := w.Snapshot()
		snapshotDuration := time.Since(snapshotStarted)
		if err != nil {
			w.markFailure(err)
			log.Printf("OTLens telemetry snapshot failed: %v", err)
			return
		}
		snapshot.SensorID = w.Client.cfg.SensorID
		if snapshot.CapturedAt.IsZero() {
			snapshot.CapturedAt = time.Now().UTC()
		}
		if snapshotDuration >= 2*time.Second {
			log.Printf("OTLens telemetry snapshot slow: duration=%s topology_bytes=%d alerts_bytes=%d dns_bytes=%d smb_bytes=%d protocol_bytes=%d", snapshotDuration, len(snapshot.Topology), len(snapshot.Alerts), len(snapshot.DNSObservations), len(snapshot.SMBObservations), len(snapshot.ProtocolObservations))
		}
		w.mu.Lock()
		nextSequence := w.sequence + 1
		if nowSequence := time.Now().UTC().UnixNano(); nowSequence > nextSequence {
			nextSequence = nowSequence
		}
		w.pending = 1
		w.mu.Unlock()
		snapshot.Sequence = nextSequence
		snapshot.BatchID = fmt.Sprintf("%s-%d", w.Client.cfg.SensorID, nextSequence)
		checksumInput := snapshot
		checksumInput.Checksum = ""
		payload, _ := json.Marshal(checksumInput)
		sum := sha256.Sum256(payload)
		snapshot.Checksum = hex.EncodeToString(sum[:])

		var uploadErr error
		telemetryTimeout := w.Client.TelemetryTimeout()
		w.markAttempt()
		uploadStarted := time.Now()
		for attempt := 1; attempt <= 3; attempt++ {
			requestCtx, cancel := context.WithTimeout(ctx, telemetryTimeout)
			_, uploadErr = w.Client.PushTelemetry(requestCtx, snapshot)
			cancel()
			if uploadErr == nil {
				w.markSuccess(nextSequence)
				if d := time.Since(uploadStarted); d >= 2*time.Second {
					log.Printf("OTLens telemetry upload completed slowly: duration=%s payload_bytes=%d topology_bytes=%d alerts_bytes=%d", d, len(payload), len(snapshot.Topology), len(snapshot.Alerts))
				}
				if w.Detect != nil && len(snapshot.Alerts) > 0 {
					var sent []*detect.Alert
					if json.Unmarshal(snapshot.Alerts, &sent) == nil {
						w.Detect.MarkAlertsSynced(sent)
					}
				}
				if w.Flow != nil {
					states := make([]flow.SyncSnapshot, 0, len(snapshot.FlowSync))
					for _, item := range snapshot.FlowSync {
						states = append(states, flow.SyncSnapshot{
							ID: item.ID, InitiatorIP: item.InitiatorIP, ResponderIP: item.ResponderIP,
							InitiatorPort: item.InitiatorPort, ResponderPort: item.ResponderPort,
							PacketsAToB: item.PacketsAToB, PacketsBToA: item.PacketsBToA, BytesAToB: item.BytesAToB, BytesBToA: item.BytesBToA,
							Packets: item.Packets, Bytes: item.Bytes, LastSeen: item.LastSeen, VLANID: item.VLANID,
						})
					}

					// Backward-compatible fallback for custom snapshot providers/tests that
					// have not populated FlowSync yet. Production snapshots carry FlowSync
					// for *all* selected dirty flows, including flows deliberately omitted
					// from the public topology graph.
					if len(states) == 0 && len(snapshot.Topology) > 0 {
						var sentGraph struct {
							Edges []struct {
								ID            string    `json:"ID"`
								InitiatorIP   string    `json:"InitiatorIP"`
								ResponderIP   string    `json:"ResponderIP"`
								InitiatorPort uint16    `json:"InitiatorPort"`
								ResponderPort uint16    `json:"ResponderPort"`
								PacketsAToB   uint64    `json:"PacketsAToB"`
								PacketsBToA   uint64    `json:"PacketsBToA"`
								BytesAToB     uint64    `json:"BytesAToB"`
								BytesBToA     uint64    `json:"BytesBToA"`
								Packets       uint64    `json:"Packets"`
								Bytes         uint64    `json:"Bytes"`
								LastSeen      time.Time `json:"LastSeen"`
								VLANID        uint16    `json:"VLANID"`
							} `json:"Edges"`
						}
						if json.Unmarshal(snapshot.Topology, &sentGraph) == nil {
							for _, item := range sentGraph.Edges {
								states = append(states, flow.SyncSnapshot{
									ID: item.ID, InitiatorIP: item.InitiatorIP, ResponderIP: item.ResponderIP,
									InitiatorPort: item.InitiatorPort, ResponderPort: item.ResponderPort,
									PacketsAToB: item.PacketsAToB, PacketsBToA: item.PacketsBToA, BytesAToB: item.BytesAToB, BytesBToA: item.BytesBToA,
									Packets: item.Packets, Bytes: item.Bytes, LastSeen: item.LastSeen, VLANID: item.VLANID,
								})
							}
						}
					}
					if len(states) > 0 {
						w.Flow.MarkFlowsSynced(states)
					}
				}
				break
			}
			if currentSequence, conflict := TelemetrySequenceConflict(uploadErr); conflict {
				w.mu.Lock()
				if currentSequence > w.sequence {
					w.sequence = currentSequence
				}
				w.pending = 1
				w.mu.Unlock()
				log.Printf("OTLens telemetry sequence resynchronized with Central: current=%d rejected=%d", currentSequence, nextSequence)
				return
			}
			if IsSensorAuthError(uploadErr) {
				w.markUnregistered()
				break
			}
			if IsSensorResetPendingError(uploadErr) {
				// This is expected coordination with Data Management, not a sync
				// failure. The next cycle pulls/applies the reset command first.
				break
			}
			if attempt < 3 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(attempt) * 2 * time.Second):
				}
			}
		}
		if uploadErr != nil {
			if IsSensorResetPendingError(uploadErr) {
				log.Printf("OTLens telemetry deferred while Central reset is pending")
				return
			}
			// ConsecutiveFailures means failed synchronization *cycles*, not HTTP
			// retry attempts. Counting each of the three retries separately made
			// the UI report 27 failures after only nine failed sync cycles and
			// incorrectly escalated health much faster than intended.
			w.markFailure(uploadErr)
			if IsSensorAuthError(uploadErr) {
				log.Printf("OTLens Central sensor credential is no longer accepted; re-enrollment will be attempted: %v", uploadErr)
				return
			}
			log.Printf("OTLens telemetry upload failed after retries: %v (timeout=%s payload_bytes=%d topology_bytes=%d alerts_bytes=%d)", uploadErr, telemetryTimeout, len(payload), len(snapshot.Topology), len(snapshot.Alerts))
		}
	}

	// PCAP analysis can take minutes. It must never block heartbeat and telemetry
	// delivery, therefore only one analysis poll/run is allowed asynchronously.
	if w.ProcessAnalysis != nil {
		w.analysisMu.Lock()
		if !w.analysisRunning {
			w.analysisRunning = true
			go func() {
				defer func() { w.analysisMu.Lock(); w.analysisRunning = false; w.analysisMu.Unlock() }()
				w.ProcessAnalysis(ctx)
			}()
		}
		w.analysisMu.Unlock()
	}
}
