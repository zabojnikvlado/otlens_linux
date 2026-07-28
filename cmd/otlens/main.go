// Command otlens is OTLens's main entry point: loads the Linux sensor config file,
// wires up every engine via internal/app, and runs until interrupted
// (Ctrl+C / SIGTERM), flushing persisted state cleanly on the way
// out. See README.md for configuration and the API surface.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"github.com/zabojnikvlado/otlens_linux/internal/topology"
	"syscall"

	"github.com/zabojnikvlado/otlens_linux/internal/app"
	"github.com/zabojnikvlado/otlens_linux/internal/capture"
	"github.com/zabojnikvlado/otlens_linux/internal/config"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/oui"
	"github.com/zabojnikvlado/otlens_linux/internal/recon"
	"github.com/zabojnikvlado/otlens_linux/internal/syncagent"
	"go.uber.org/zap"
)

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	configPath := flag.String("config", "/etc/otlens/config.yaml", "path to the Linux sensor configuration file")
	flag.Parse()

	// Config has to load before the logger can be initialized (its
	// level comes from cfg.Logging.Level), so a config failure here
	// is the one place in the program that can't log through zap.
	cfg, err := config.Load(*configPath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration loading failed: %v\n", err)
		os.Exit(1)
	}

	if err := logger.Init(
		cfg.Logging.Level,
		cfg.Logging.Output,
		logger.RotationConfig{
			Enabled:    cfg.Logging.Rotation.Enabled,
			MaxSizeMB:  cfg.Logging.Rotation.MaxSizeMB,
			MaxBackups: cfg.Logging.Rotation.MaxBackups,
			MaxAgeDays: cfg.Logging.Rotation.MaxAgeDays,
			Compress:   cfg.Logging.Rotation.Compress,
		},
	); err != nil {
		panic(err)
	}

	defer logger.Sync()

	logger.Log.Info("OTLens starting")

	logger.Log.Info(
		"Configuration loaded",
		zap.String("logging_level", cfg.Logging.Level),
		zap.Strings("logging_output", cfg.Logging.Output),
	)

	logger.Log.Info(
		"Capture interface",
		zap.String(
			"interface",
			cfg.Capture.Interface,
		),
	)

	libpcapVersion := "not used"
	if strings.EqualFold(cfg.Capture.Mode, "pcap") || strings.TrimSpace(cfg.Capture.Mode) == "" {
		libpcapVersion = capture.LibpcapVersion()
		if err := capture.ValidateLibpcapVersion(libpcapVersion); err != nil {
			logger.Log.Fatal("Unsupported packet capture backend", zap.String("libpcap", libpcapVersion), zap.Error(err))
		}
		logger.Log.Info("Packet capture backend",
			zap.String("backend", "libpcap"),
			zap.String("version", libpcapVersion),
			zap.String("minimum_supported", capture.MinimumLibpcapVersion),
		)
	}

	logger.Log.Info(
		"OTLens ready",
	)

	if cfg.OUI.CSVPath != "" {

		if err := oui.LoadCSV(cfg.OUI.CSVPath); err != nil {

			logger.Log.Warn(
				"Loading OUI vendor database failed, falling back to built-in list",
				zap.String("path", cfg.OUI.CSVPath),
				zap.Error(err),
			)

		} else {

			logger.Log.Info(
				"OUI vendor database loaded",
				zap.String("path", cfg.OUI.CSVPath),
			)
		}
	}

	application, err := app.New(cfg)

	if err != nil {

		logger.Log.Fatal(
			"Application initialization failed",
			zap.Error(err),
		)
	}

	application.Start()

	ctx, cancel := context.WithCancel(context.Background())
	if cfg.Central.Enabled {
		hostname, _ := os.Hostname()
		client := syncagent.New(syncagent.Config{
			BaseURL: cfg.Central.URL, Token: cfg.Central.Token, SensorID: cfg.Central.SensorID,
			Name: cfg.Central.Name, SiteID: cfg.Central.SiteID, Version: cfg.App.Version, Hostname: hostname,
			Interval: cfg.Central.Interval, Timeout: cfg.Central.Timeout, InsecureSkipVerify: cfg.Central.InsecureSkipVerify,
		})
		marshal := func(v interface{}) (json.RawMessage, error) {
			b, err := json.Marshal(v)
			return json.RawMessage(b), err
		}
		metricStarted := time.Now()
		var previousMetricAt time.Time
		var previousPackets, previousBytes, previousTCPSegments uint64
		metricsSnapshot := func() map[string]interface{} {
			now := time.Now()
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			tcp := application.TCPReassembler.Stats()
			var packets, bytes uint64
			captureRunning := false
			if application.CaptureEngine != nil {
				packets, bytes, captureRunning = application.CaptureEngine.Stats()
			}
			elapsed := now.Sub(previousMetricAt).Seconds()
			if previousMetricAt.IsZero() || elapsed <= 0 {
				elapsed = cfg.Central.Interval.Seconds()
				if elapsed <= 0 {
					elapsed = 30
				}
			}
			packetDelta, byteDelta := uint64(0), uint64(0)
			if packets >= previousPackets {
				packetDelta = packets - previousPackets
			}
			if bytes >= previousBytes {
				byteDelta = bytes - previousBytes
			}
			packetsPerSecond := float64(packetDelta) / elapsed
			bytesPerSecond := float64(byteDelta) / elapsed
			tcpSegmentDelta := uint64(0)
			if tcp.SegmentsSeen >= previousTCPSegments {
				tcpSegmentDelta = tcp.SegmentsSeen - previousTCPSegments
			}
			tcpPacketsPerSecond := float64(tcpSegmentDelta) / elapsed
			tcpPacketPercent := float64(0)
			if packetDelta > 0 {
				tcpPacketPercent = float64(tcpSegmentDelta) * 100 / float64(packetDelta)
			}
			previousMetricAt, previousPackets, previousBytes, previousTCPSegments = now, packets, bytes, tcp.SegmentsSeen
			return map[string]interface{}{
				"schema_version": 4,
				"system": map[string]interface{}{
					"goroutines": runtime.NumGoroutine(), "memory_alloc_bytes": mem.Alloc,
					"memory_sys_bytes": mem.Sys, "heap_objects": mem.HeapObjects,
				},
				"capture": map[string]interface{}{
					"running": captureRunning, "packets_per_second": packetsPerSecond, "bytes_per_second": bytesPerSecond,
					"packets_total": packets, "bytes_total": bytes,
					"kernel_drops_total": 0, "interface_drops_total": 0, "drop_rate_percent": 0,
				},
				"tcp_reassembly": map[string]interface{}{
					"enabled": tcp.Enabled, "running": tcp.Running,
					"active_connections": tcp.ActiveConnections, "connections_opened_total": tcp.ConnectionsOpened, "connections_closed_total": tcp.ConnectionsClosed,
					"segments_seen": tcp.SegmentsSeen, "bytes_seen": tcp.BytesSeen, "chunks_emitted": tcp.ChunksEmitted, "bytes_emitted": tcp.BytesEmitted,
					"tcp_packets_per_second": tcpPacketsPerSecond, "tcp_packet_percent": tcpPacketPercent,
					"buffered_bytes": tcp.BufferedBytes, "out_of_order_segments": tcp.OutOfOrderSegments, "retransmitted_bytes": tcp.RetransmittedBytes,
					"overlap_segments": tcp.OverlapSegments, "overlap_conflicts": tcp.OverlapConflicts, "gap_recoveries": tcp.GapRecoveries,
					"evicted_connections": tcp.EvictedConnections, "dropped_segments": tcp.DroppedSegments,
				},
				"pipeline": map[string]interface{}{
					"event_queue_depth": 0, "event_queue_percent": 0, "events_per_second": packetsPerSecond, "dropped_events_total": 0,
				},
				"uptime_seconds": int64(time.Since(metricStarted).Seconds()),
			}
		}
		worker := &syncagent.Worker{
			Metrics: metricsSnapshot,
			Uptime:  func() int64 { return int64(time.Since(metricStarted).Seconds()) },
			Client:  client, Detect: application.DetectEngine, Flow: application.FlowEngine, ThreatIntel: application.ThreatIntel, ApplyCommand: func(command management.Command) {
				switch command.Type {
				case "recon.safe_discovery":
					var rc management.ReconCommand
					if err := json.Unmarshal([]byte(command.Target), &rc); err != nil {
						log.Printf("OTLens invalid reconnaissance command: %v", err)
						break
					}
					go func() {
						runCtx, cancel := context.WithTimeout(context.Background(), time.Duration(maxInt(30, len(rc.Targets)*len(rc.Policy.Ports)*maxInt(1, rc.Policy.TimeoutSeconds)+30))*time.Second)
						defer cancel()
						results := recon.Run(runCtx, rc)
						runErr := ""
						if runCtx.Err() != nil {
							runErr = runCtx.Err().Error()
						}
						var uploadErr error
						for attempt := 1; attempt <= 6; attempt++ {
							uploadCtx, uploadCancel := context.WithTimeout(context.Background(), 20*time.Second)
							uploadErr = client.PushReconResult(uploadCtx, rc.JobID, results, runErr)
							uploadCancel()
							if uploadErr == nil {
								break
							}
							log.Printf("OTLens reconnaissance result upload attempt %d failed: %v", attempt, uploadErr)
							if attempt < 6 {
								time.Sleep(time.Duration(attempt*5) * time.Second)
							}
						}
						if uploadErr != nil {
							log.Printf("OTLens reconnaissance result upload permanently failed for job %s: %v", rc.JobID, uploadErr)
						}
					}()
				case "sensor.capture.stop":
					if application.CaptureEngine != nil {
						application.CaptureEngine.Stop()
					} else if application.IPFIXEngine != nil {
						application.IPFIXEngine.Stop()
					}
					log.Printf("OTLens sensor capture stopped by Central command")
				case "sensor.database.reset", "sensor.factory.reset", "sensor.learning.reset", "sensor.assets.reset", "sensor.alerts.reset", "sensor.tags.reset", "sensor.analysis.reset":
					op := strings.TrimSuffix(strings.TrimPrefix(command.Type, "sensor."), ".reset")
					if err := application.Snapshotter.Reset(op); err != nil {
						log.Printf("OTLens sensor reset failed: %v", err)
					} else {
						log.Printf("OTLens sensor %s reset completed", op)
					}
				case "sensor.backup.create":
					name := strings.TrimSpace(command.Target)
					path, err := application.Snapshotter.Backup(filepath.Join(filepath.Dir(cfg.Persist.Path), "backups"), name)
					if err != nil {
						log.Printf("OTLens sensor backup failed: %v", err)
					} else {
						log.Printf("OTLens sensor backup created: %s", path)
					}
				case "sensor.capture.start":
					go func() {
						var err error
						if application.CaptureEngine != nil {
							if application.CaptureEngine.IsRunning() {
								return
							}
							err = application.CaptureEngine.Start()
						} else if application.IPFIXEngine != nil {
							if application.IPFIXEngine.IsRunning() {
								return
							}
							err = application.IPFIXEngine.Start()
						}
						if err != nil {
							log.Printf("OTLens sensor capture start failed: %v", err)
						}
					}()
				case "asset.confirm":
					application.AssetEngine.Confirm(command.Target)
				case "asset.delete":
					application.AssetEngine.Delete(command.Target)
				case "alert.approve":
					application.DetectEngine.ApproveAlert(command.Target)
				case "alert.confirm":
					application.DetectEngine.ConfirmAlert(command.Target)
				case "rule.add", "rule.upsert":
					var rule detect.Rule
					if err := json.Unmarshal([]byte(command.Target), &rule); err != nil {
						log.Printf("OTLens invalid %s command: %v", command.Type, err)
						break
					}
					if command.Type == "rule.add" {
						if _, err := application.DetectEngine.AddPolicyRule(&rule); err != nil {
							log.Printf("OTLens rule creation failed: %v", err)
						}
					} else if err := application.DetectEngine.UpsertPolicyRule(&rule); err != nil {
						log.Printf("OTLens rule update failed: %v", err)
					}
				case "rule.toggle":
					var request struct {
						ID      string `json:"id"`
						Enabled bool   `json:"enabled"`
					}
					if err := json.Unmarshal([]byte(command.Target), &request); err == nil {
						application.DetectEngine.ToggleRule(request.ID, request.Enabled)
					}
				case "rule.delete":
					application.DetectEngine.DeleteRule(command.Target)
				case "segmentation.config":
					var request struct {
						VLANLevels   map[uint16]float64 `json:"vlan_levels"`
						MaxLevelJump float64            `json:"max_level_jump"`
					}
					if err := json.Unmarshal([]byte(command.Target), &request); err == nil {
						application.DetectEngine.UpdateSegmentationConfig(request.VLANLevels, request.MaxLevelJump)
					}
				}
			}, Versions: func() map[string]string {
				return map[string]string{
					"otlens":   cfg.App.Version,
					"go":       runtime.Version(),
					"libpcap":  libpcapVersion,
					"gopacket": "v1.1.19",
				}
			}, CaptureInfo: func() map[string]interface{} {
				backend := "ipfix"
				if application.CaptureEngine != nil {
					backend = "libpcap"
				}
				return map[string]interface{}{
					"backend":     backend,
					"interface":   cfg.Capture.Interface,
					"snaplen":     cfg.Capture.Snaplen,
					"promiscuous": cfg.Capture.Promiscuous,
				}
			}, Health: func() map[string]string {
				running := false
				if application.CaptureEngine != nil {
					running = application.CaptureEngine.IsRunning()
				} else if application.IPFIXEngine != nil {
					running = application.IPFIXEngine.IsRunning()
				}
				status := "stopped"
				if running {
					status = "running"
				}
				return map[string]string{"capture": status, "mode": application.CaptureMode}
			}, ProcessAnalysis: func(jobCtx context.Context) {
				job, err := client.NextAnalysisJob(jobCtx)
				if err != nil {
					log.Printf("OTLens analysis job poll failed: %v", err)
					return
				}
				if job == nil {
					return
				}
				result := management.AnalysisResult{Protocols: job.Protocols}
				if application.CaptureEngine == nil {
					result.Error = "PCAP analysis requires capture engine"
					_ = client.PushAnalysisResult(jobCtx, job.ID, result)
					return
				}
				ext := filepath.Ext(job.Filename)
				if ext != ".pcapng" {
					ext = ".pcap"
				}
				tmp, err := os.CreateTemp("", "otlens-analysis-*"+ext)
				if err != nil {
					result.Error = err.Error()
					_ = client.PushAnalysisResult(jobCtx, job.ID, result)
					return
				}
				path := tmp.Name()
				_ = tmp.Close()
				defer os.Remove(path)
				if err := client.DownloadAnalysisPCAP(jobCtx, job.ID, path); err != nil {
					result.Error = err.Error()
					_ = client.PushAnalysisResult(jobCtx, job.ID, result)
					return
				}
				if data, err := os.ReadFile(path); err != nil {
					result.Error = err.Error()
					_ = client.PushAnalysisResult(jobCtx, job.ID, result)
					return
				} else if sum := sha256.Sum256(data); job.SHA256 != "" && hex.EncodeToString(sum[:]) != job.SHA256 {
					result.Error = "downloaded PCAP SHA-256 mismatch"
					_ = client.PushAnalysisResult(jobCtx, job.ID, result)
					return
				}
				assetsBefore, flowsBefore, tagsBefore, alertsBefore := len(application.AssetEngine.GetAll()), len(application.FlowEngine.GetAll()), len(application.StoreEngine.GetTags()), len(application.DetectEngine.GetAlerts())
				wasRunning := application.CaptureEngine.IsRunning()
				if wasRunning {
					// Stop() only requests shutdown. Wait for the old capture loop to
					// release its running flag before replaying the PCAP; otherwise the
					// restart below races it and fails with "capture already running",
					// leaving the sensor permanently without live flow detection.
					if err := application.CaptureEngine.StopAndWait(5 * time.Second); err != nil {
						result.Error = fmt.Sprintf("stopping live capture before analysis failed: %v", err)
						_ = client.PushAnalysisResult(jobCtx, job.ID, result)
						return
					}
				}
				packets, analyzeErr := application.CaptureEngine.AnalyzeFile(path)
				if wasRunning {
					// Start blocks for the lifetime of the capture session. Run it in its
					// own goroutine so analysis completion and telemetry synchronization
					// can continue after live capture has been restored.
					go func() {
						if err := application.CaptureEngine.Start(); err != nil {
							log.Printf("OTLens capture restart after PCAP analysis failed: %v", err)
						}
					}()
				}
				result.Packets = packets
				result.AssetsDiscovered = max(0, len(application.AssetEngine.GetAll())-assetsBefore)
				result.FlowsDiscovered = max(0, len(application.FlowEngine.GetAll())-flowsBefore)
				result.TagsDiscovered = max(0, len(application.StoreEngine.GetTags())-tagsBefore)
				result.AlertsGenerated = max(0, len(application.DetectEngine.GetAlerts())-alertsBefore)
				if analyzeErr != nil {
					result.Error = analyzeErr.Error()
				}
				if err := client.PushAnalysisResult(jobCtx, job.ID, result); err != nil {
					log.Printf("OTLens analysis result upload failed: %v", err)
				}
			}, Snapshot: func() (management.TelemetrySnapshot, error) {
				graph := topology.Build(application.AssetEngine.GetAll(), application.FlowEngine.GetDirtyFlows(), application.StoreEngine.GetTags(), cfg.ICS.ModbusPort, cfg.ICS.S7Port, cfg.Deception.HoneypotThreshold)
				graphJSON, err := marshal(graph)
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				tagsJSON, err := marshal(application.StoreEngine.GetTags())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				changesJSON, err := marshal(application.StoreEngine.GetValueChanges())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				eventsJSON, err := marshal(application.StoreEngine.GetControlEvents())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				alertsJSON, err := marshal(application.DetectEngine.GetDirtyAlerts())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				baselineJSON, err := marshal(application.DetectEngine.BaselineStatus())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				dnsJSON, err := marshal(application.DNSEngine.GetObservations())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				smbJSON, err := marshal(application.SMBEngine.GetObservations())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				rulesJSON, err := marshal(application.DetectEngine.GetRules())
				if err != nil {
					return management.TelemetrySnapshot{}, err
				}
				return management.TelemetrySnapshot{SensorID: cfg.Central.SensorID, CapturedAt: time.Now().UTC(), Topology: graphJSON, Tags: tagsJSON, TagChanges: changesJSON, TagEvents: eventsJSON, Alerts: alertsJSON, Baseline: baselineJSON, Rules: rulesJSON, DNSObservations: dnsJSON, SMBObservations: smbJSON}, nil
			}}
		go worker.Run(ctx)
		logger.Log.Info("Central synchronization started", zap.String("url", cfg.Central.URL), zap.String("sensor_id", cfg.Central.SensorID))
	}

	// Run until interrupted (Ctrl+C, or a service manager stopping
	// the process) instead of exiting after a fixed sleep.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	cancel()

	application.Shutdown()

}
