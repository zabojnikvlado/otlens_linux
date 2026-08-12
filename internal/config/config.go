// Package config loads and validates configs/sensor.config.example.yaml (via
// viper) into a single Config struct that internal/app then threads
// out to every engine's constructor. This is the one place default
// values are defined — see Load's viper.SetDefault calls — so a
// setting can be safely omitted from config.yaml entirely and still
// behave sensibly.
package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type ThreatIntelIndicator struct {
	Type       string `mapstructure:"type"`
	Value      string `mapstructure:"value"`
	Provider   string `mapstructure:"provider"`
	ThreatType string `mapstructure:"threat_type"`
	Confidence int    `mapstructure:"confidence"`
}

type ThreatIntelFeed struct {
	Name          string `mapstructure:"name"`
	URL           string `mapstructure:"url"`
	Path          string `mapstructure:"path"`
	Format        string `mapstructure:"format"`
	IndicatorType string `mapstructure:"indicator_type"`
	Confidence    int    `mapstructure:"confidence"`
}

type Config struct {
	App struct {
		Name    string
		Version string
	}

	// Debug controls internal/debug — a raw stdout dump of every
	// parsed packet/ICS message, meant only for verifying capture/
	// parsing against real traffic during setup, not for a running
	// deployment (unstructured, unconditional-volume console output).
	// Off by default; the dashboard's Assets/Flows/OT Tags/Alerts
	// tabs are the structured equivalent for normal use.
	Debug struct {
		Enabled bool
	}

	Central struct {
		Enabled            bool          `mapstructure:"enabled"`
		URL                string        `mapstructure:"url"`
		SensorID           string        `mapstructure:"sensor_id"`
		Name               string        `mapstructure:"name"`
		SiteID             string        `mapstructure:"site_id"`
		Token              string        `mapstructure:"token"`
		CredentialFile     string        `mapstructure:"credential_file"`
		Interval           time.Duration `mapstructure:"interval"`
		Timeout            time.Duration `mapstructure:"timeout"`
		InsecureSkipVerify bool          `mapstructure:"insecure_skip_verify"`
	}

	Capture struct {
		// Mode selects the traffic data source: "pcap" (default —
		// live packet capture via Npcap/libpcap, needs admin/root and
		// a real NIC) or "ipfix" (receive flow records exported by a
		// router/switch/probe over UDP — no local capture privileges
		// needed at all, but flow-level only: no packet payload, so
		// ICS decoding, ARP spoofing detection, and MAC-based asset
		// identity are unavailable in this mode — see internal/ipfix's
		// package doc comment for the full tradeoff).
		Mode string

		Interface   string
		Snaplen     int32
		Promiscuous bool
		BPFFilter   string

		// IPFIX settings, only used when Mode is "ipfix".
		TCPReassembly struct {
			Enabled               bool          `mapstructure:"enabled"`
			MaxConnections        int           `mapstructure:"max_connections"`
			MaxBufferPerDirection int           `mapstructure:"max_buffer_per_direction"`
			MaxTotalBuffer        int           `mapstructure:"max_total_buffer"`
			IdleTimeout           time.Duration `mapstructure:"idle_timeout"`
			ClosedTimeout         time.Duration `mapstructure:"closed_timeout"`
			MaxOutOfOrderSegments int           `mapstructure:"max_out_of_order_segments"`
			MaxSequenceGap        uint32        `mapstructure:"max_sequence_gap"`
			GapRecoveryTimeout    time.Duration `mapstructure:"gap_recovery_timeout"`
			ShardCount            int           `mapstructure:"shard_count"`
			OverlapPolicy         string        `mapstructure:"overlap_policy"`
		}

		UDPConversations struct {
			Enabled                   bool          `mapstructure:"enabled"`
			MaxActive                 int           `mapstructure:"max_active"`
			MaxPacketsPerConversation uint64        `mapstructure:"max_packets_per_conversation"`
			MaxPendingRequests        int           `mapstructure:"max_pending_requests_per_conversation"`
			IdleTimeout               time.Duration `mapstructure:"idle_timeout"`
			RetainPayload             bool          `mapstructure:"retain_payload"`
			Protocols                 struct {
				DNS struct {
					Timeout time.Duration `mapstructure:"timeout"`
				} `mapstructure:"dns"`
				DHCP struct {
					Timeout time.Duration `mapstructure:"timeout"`
				} `mapstructure:"dhcp"`
				SNMP struct {
					Timeout time.Duration `mapstructure:"timeout"`
				} `mapstructure:"snmp"`
				SIP struct {
					Timeout time.Duration `mapstructure:"timeout"`
				} `mapstructure:"sip"`
			} `mapstructure:"protocols"`
		} `mapstructure:"udp_conversations"`

		IPFIX struct {
			// ListenAddr is the UDP address to receive IPFIX export
			// packets on, e.g. "0.0.0.0:4739" (4739 is IPFIX's
			// IANA-assigned default port).
			ListenAddr string
		}
	}

	// ICS controls OT/ICS protocol decoding — see internal/ics.
	ICS struct {
		// ModbusPort/S7Port let a deployment that runs these
		// protocols on non-standard ports still be decoded. 0 falls
		// back to the standard port (502/102).
		ModbusPort     uint16
		S7Port         uint16
		EtherNetIPPort uint16
		DNP3Port       uint16
		OPCUAPort      uint16
		BACnetPort     uint16
		IEC104Port     uint16
	}

	Baseline struct {
		// Enabled controls whether the learning phase runs at all.
		// true (default): learn "normal" for LearningDuration before
		// alerting on anything new. false: skip learning entirely —
		// the engine starts directly in monitoring mode with nothing
		// pre-approved, so every device/communication is flagged as
		// new from the very first packet. Set this false for a
		// deployment where the network's baseline is already known/
		// trusted and there's no reason to wait out a learning
		// window before real alerting starts.
		Enabled bool

		// How long to learn "normal" asset-to-asset communication
		// before raising alerts for anything not seen during this
		// window. Go duration syntax, e.g. "10m", "1h", "24h". Only
		// used when Enabled is true.
		LearningDuration time.Duration

		// BehaviorEnabled enables the modular statistical baseline consumed by
		// Network Behavior Analytics. The legacy seen/not-seen detection
		// baseline remains controlled by Enabled above.
		BehaviorEnabled  bool
		BucketDuration   time.Duration
		MaxProfiles      int
		MaxAssetProfiles int

		// Readiness/maturity controls. LearningDuration is the minimum time;
		// the behavior baseline may continue until the observed network is stable
		// enough, capped by MaxLearningMultiplier.
		MinAssetSamples       int
		MinAssetAge           time.Duration
		ReadinessThreshold    float64
		MaxLearningMultiplier float64
		CandidateMinSamples   int
		CandidateMinDays      int
		MinStatSamples        int
		// Optional UTC maintenance windows, e.g. "weekend@02:00-04:00" or
		// "mon,tue@22:00-23:00". Maintenance traffic is learned under a
		// separate maintenance context and never contaminates production behavior.
		MaintenanceWindows []string
	}

	NBA struct {
		Enabled                  bool
		MinScore                 float64
		MaxAnomalies             int
		Cooldown                 time.Duration
		RiskEnabled              bool
		MaxAssessments           int
		CorrelationEnabled       bool
		CorrelationWindow        time.Duration
		FindingExpireAfter       time.Duration
		MaxFindings              int
		MaxAssessmentsPerFinding int
		MinFindingScore          float64
		AlertThreshold           float64
		IncidentThreshold        float64
	}

	// Deception configures deliberately-planted decoy/honeypot
	// stations for lateral-movement detection — see
	// internal/detect's honeypot.go. A station is any known-static
	// device (typically one you deployed specifically as a decoy,
	// but the mechanism works for any asset you want to assign a
	// non-default risk weight to) identified by IP with an assigned
	// Score. Nothing legitimate should ever have a real reason to
	// talk to or from a genuine honeypot, which is what makes it
	// such a low-false-positive signal: any traffic touching one is
	// inherently suspicious in a way that "a new device appeared" or
	// "unexpected communication pattern" (baseline learning's alerts)
	// aren't.
	Deception struct {

		// HoneypotThreshold is the Score at or above which a station
		// is treated as a honeypot for alerting purposes (not just a
		// "somewhat more important than usual" asset) — see
		// asset.Asset.Score and honeypot.go.
		HoneypotThreshold int

		Stations []struct {
			IP    string
			Score int
		}
	}

	// Detect controls the anomaly/rule detection engine's tunables
	// that aren't baseline-learning-specific — see internal/detect.
	Detect struct {
		// How many consecutive conflicting ARP claims are required before a
		// duplicate-IP/gateway-identity alert is escalated. Repetition never
		// auto-trusts a new MAC; analyst approval is required.
		ARPConfirmThreshold int

		// Segmentation flags traffic that jumps too many Purdue Model
		// levels directly (e.g. a Level 1 field device talking straight
		// to a Level 4/5 business system, skipping the DMZ) — see
		// internal/detect/segmentation.go. Off by default: it needs
		// VLANLevels filled in to mean anything, and a wrong/incomplete
		// mapping would just generate noise.
		Segmentation struct {
			Enabled bool
			// VLANLevels maps a VLAN ID to its Purdue Model level
			// (typically 0-5; half-levels like 3.5 for a DMZ are fine).
			// A VLAN not listed here is treated as unclassified and
			// never participates in a violation check — both sides of
			// a flow need a known level for this rule to evaluate it.
			VLANLevels map[uint16]float64
			// MaxLevelJump is how many levels apart two VLANs may
			// communicate directly before it's flagged. 1 (the
			// default) allows adjacent-level traffic (e.g. Level 2 to
			// Level 3) but flags anything that skips a level.
			MaxLevelJump float64
			// Policy is an optional explicit zone matrix evaluated before the
			// Purdue-level fallback. Use "*"/"any" as wildcards.
			Policy []struct {
				SourceZone      string
				DestinationZone string
				Protocol        string
				Direction       string
				Allowed         bool
			}
		}

		// Reconnaissance flags a source IP that contacts an unusually
		// large number of distinct destination hosts (network/host
		// scan) or distinct ports on one destination (port scan)
		// within a short rolling window — see
		// internal/detect/reconnaissance.go. On by default with
		// conservative thresholds; a legitimate host that's supposed
		// to talk to many others (a monitoring server, a DNS
		// resolver) may need its own suppression or a higher
		// threshold for a noisy network.
		Reconnaissance struct {
			Enabled           bool
			Window            time.Duration
			HostScanThreshold int
			PortScanThreshold int
		}

		// ThreatIntel matches observed IP addresses and DNS names against
		// configured static indicators and periodically refreshed feeds.
		ThreatIntel struct {
			Enabled            bool
			RefreshInterval    time.Duration
			HTTPTimeout        time.Duration
			MaxDNSObservations int
			Static             []ThreatIntelIndicator
			Feeds              []ThreatIntelFeed
		}

		// C2Beacon flags a source IP whose outbound TCP connections to
		// one external destination+port happen at a suspiciously
		// regular interval — the classic "beaconing" pattern malware
		// uses to check in with a command-and-control server. See
		// internal/detect/c2beacon.go for exactly how "suspiciously
		// regular" is measured. This is a behavioral heuristic, not a
		// known-bad-IP match (OTLens has no threat-intel feed) — it
		// will also flag a legitimate periodic external service (a
		// license check-in, a monitoring agent phoning a SaaS
		// dashboard) if its timing happens to be regular enough; that's
		// a false positive worth tuning MinSamples/MaxCoefficientOfVariation
		// for, not a sign the whole approach is wrong.
		OTValueAnomaly struct {
			Enabled          bool
			MinSamples       int
			ZScoreThreshold  float64
			RateMultiplier   float64
			StuckAfter       time.Duration
			MissingAfter     time.Duration
			ToggleWindow     time.Duration
			ToggleThreshold  int
			UnexpectedWrites bool
			CheckInterval    time.Duration
		}
		LateralMovement struct {
			Enabled            bool
			Window             time.Duration
			FanOutThreshold    int
			LargeTransferBytes uint64
			PivotWindow        time.Duration
			AdminPorts         []uint16
		}
		C2Correlation struct {
			Enabled                  bool
			MinScore                 int
			DNSWindow                time.Duration
			NXDomainThreshold        int
			UniqueSubdomainThreshold int
			LongLabelLength          int
		}

		C2Beacon struct {
			Enabled bool
			// MinSamples is how many connection attempts to the same
			// destination+port must be seen before timing is judged at
			// all — too few and normal variance looks artificially
			// regular.
			MinSamples int
			// MaxCoefficientOfVariation is stddev/mean of the intervals
			// between connections. Lower means more regular; 0 would be
			// a perfect metronome. 0.15 (the default) is fairly strict —
			// real beacon malware is often *more* regular than this,
			// human-driven traffic essentially never is.
			MaxCoefficientOfVariation float64
			// MinInterval/MaxInterval bound what counts as "beacon-like"
			// timing at all — faster than MinInterval looks like retries
			// or keepalives, slower than MaxInterval doesn't have enough
			// occurrences within a practical observation window to judge
			// regularity with any confidence.
			MinInterval time.Duration
			MaxInterval time.Duration
			// MaxTrackedDestinations caps total memory use — the oldest
			// (least recently touched) destination is evicted once this
			// is hit, same reasoning as every other unbounded-map risk
			// this codebase has had to guard against.
			MaxTrackedDestinations int
		}
	}

	// Store controls the OT tag/register storage engine's in-memory
	// safety caps — see internal/store. These are on top of, not
	// instead of, Persist.Retention's time-based pruning: they exist
	// so a sudden burst can't balloon memory before the next prune
	// pass runs.
	Store struct {
		MaxValueChanges  int
		MaxControlEvents int
	}

	Persist struct {
		// Path to the local SQLite database file where assets, flows, tags,
		// and alerts are periodically snapshotted so a restart
		// doesn't lose everything — see internal/persist.
		Path string

		// How often to flush the current in-memory state to disk.
		// Go duration syntax, e.g. "10s", "1m". Kept infrequent on
		// purpose: bbolt commits a full fsync per write transaction,
		// so flushing on every packet would bottleneck capture.
		FlushInterval time.Duration

		// Retention is how long to keep records before pruning them,
		// based on each record's last-seen/timestamp. Go duration
		// syntax, e.g. "168h" for 7 days. Set to "0" to disable
		// pruning and keep everything forever (not recommended for
		// flows in particular — see flow.Engine.Prune).
		Retention time.Duration
	}

	// OUI controls vendor identification from MAC addresses — see
	// internal/oui. Optional: works with a small built-in fallback
	// list even if left empty.
	OUI struct {
		// CSVPath, if set, loads the official IEEE MA-L registry
		// (https://standards-oui.ieee.org/oui/oui.csv — public, no
		// account needed) for full vendor coverage, including OT/ICS
		// vendors the built-in list doesn't attempt to guess at.
		CSVPath string
	}

	Logging struct {
		// Level accepts the same names zap itself uses: "debug",
		// "info", "warn", "error".
		Level string

		// Output is where log lines are written — any combination of
		// "stdout", "stderr", or a file path. Empty/omitted defaults
		// to ["stderr"] (console only, same as before this setting
		// existed). Add a file path here to also persist logs beyond
		// the current console session — useful when running as a
		// background service with no visible console.
		Output []string

		// Rotation controls in-process log file rotation for any
		// file-path entries in Output above (stdout/stderr are never
		// rotated — rotation only makes sense for an actual file).
		// Off by default, matching the original unbounded-growth
		// behavior. Audit.Path below shares this exact same
		// configuration — see logger.RotationConfig's doc comment
		// for why a hand-rolled mechanism rather than an external
		// dependency.
		Rotation struct {
			Enabled bool

			MaxSizeMB  int  // rotate once the file reaches this size
			MaxBackups int  // keep at most this many rotated files (0 = unlimited)
			MaxAgeDays int  // delete rotated files older than this (0 = unlimited)
			Compress   bool // gzip rotated files
		}
	}
}

// CentralConfig contains configuration specific to the OTLens Central Management Server.
// It is intentionally separate from Config, which is the Linux sensor configuration.
type CentralConfig struct {
	// Web is the management/dashboard listener. The current Central build
	// exposes the Central API router here; a dedicated dashboard can use this
	// listener without sharing the sensor-facing port.
	Web struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
		TLS  struct {
			Enabled      bool     `mapstructure:"enabled"`
			CertFile     string   `mapstructure:"certfile"`
			KeyFile      string   `mapstructure:"keyfile"`
			MinVersion   string   `mapstructure:"minversion"`
			CipherSuites []string `mapstructure:"ciphersuites"`
		} `mapstructure:"tls"`
	} `mapstructure:"web"`
	SensorAPI struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
		TLS  struct {
			Enabled      bool     `mapstructure:"enabled"`
			CertFile     string   `mapstructure:"certfile"`
			KeyFile      string   `mapstructure:"keyfile"`
			MinVersion   string   `mapstructure:"minversion"`
			CipherSuites []string `mapstructure:"ciphersuites"`
		} `mapstructure:"tls"`
	} `mapstructure:"sensor_api"`
	Database struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		Name     string `mapstructure:"name"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		SSLMode  string `mapstructure:"sslmode"`
	} `mapstructure:"database"`
	Auth struct {
		ManagementToken string `mapstructure:"management_token"`
		SensorToken     string `mapstructure:"sensor_token"`
		// SessionDuration is the sliding-expiry window for a logged-in
		// Central UI session (see internal/central's authMiddleware) —
		// it resets on every request, so an active user is never logged
		// out mid-session, but an idle one expires this long after their
		// last request.
		SessionDuration time.Duration `mapstructure:"session_duration"`
		// BootstrapUsername/BootstrapPassword create the protected built-in
		// administrator when it is missing (first startup, or recovery after
		// a database reset). Once that account exists, bootstrap never resets
		// its password; it only guarantees that the account still has the
		// built-in admin role and is enabled. The initial account requires an
		// immediate password change. Change these before first startup.
		BootstrapUsername string `mapstructure:"bootstrap_username"`
		BootstrapPassword string `mapstructure:"bootstrap_password"`
	} `mapstructure:"auth"`
	Analysis struct {
		Enabled         bool          `mapstructure:"enabled"`
		UploadDirectory string        `mapstructure:"upload_directory"`
		MaxUploadSizeMB int64         `mapstructure:"max_upload_size_mb"`
		JobTimeout      time.Duration `mapstructure:"job_timeout"`
		RetainPCAP      time.Duration `mapstructure:"retain_pcap"`
		AllowImport     bool          `mapstructure:"allow_import"`
	} `mapstructure:"analysis"`
	SIEM struct {
		Enabled       bool              `mapstructure:"enabled"`
		URL           string            `mapstructure:"url"`
		ExportAlerts  bool              `mapstructure:"export_alerts"`
		ExportAudit   bool              `mapstructure:"export_audit"`
		Source        string            `mapstructure:"source"`
		BearerToken   string            `mapstructure:"bearer_token"`
		Timeout       time.Duration     `mapstructure:"timeout"`
		RetryInterval time.Duration     `mapstructure:"retry_interval"`
		BatchSize     int               `mapstructure:"batch_size"`
		MaxAttempts   int               `mapstructure:"max_attempts"`
		Headers       map[string]string `mapstructure:"headers"`
		TLS           struct {
			InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
			CACertFile         string `mapstructure:"ca_cert_file"`
			ClientCertFile     string `mapstructure:"client_cert_file"`
			ClientKeyFile      string `mapstructure:"client_key_file"`
			ServerName         string `mapstructure:"server_name"`
		} `mapstructure:"tls"`
	} `mapstructure:"siem"`
	Sensors struct {
		// OfflineAfter — a sensor whose last heartbeat is older than this
		// is marked "offline" in the Sensors tab. Heartbeats normally
		// arrive every sensor.central.interval (30s by default), so this
		// should be a few multiples of that, not equal to it, to tolerate
		// a couple of missed/slow syncs without flapping the status.
		OfflineAfter time.Duration `mapstructure:"offline_after"`
		// CheckInterval is how often Central re-evaluates every sensor's
		// last heartbeat against OfflineAfter. See main.go's offline-sweep
		// goroutine.
		CheckInterval time.Duration `mapstructure:"check_interval"`
	} `mapstructure:"sensors"`
	// Vulnerability is a purely local, offline lookup — see package vuln's
	// doc comment for why this deliberately never makes a live network
	// call. CSVPath is prepared out of band from a public ICS advisory
	// feed and carried into the (often air-gapped) network like any other
	// definition update.
	Vulnerability struct {
		Enabled bool   `mapstructure:"enabled"`
		CSVPath string `mapstructure:"csv_path"`
	} `mapstructure:"vulnerability"`
	// DatabaseRetention bounds PostgreSQL growth by age and, as a backstop,
	// by total size — see internal/central/retention.go. Scope is
	// deliberately narrow: only telemetry-derived history (topology_edges,
	// topology_nodes, analysis_jobs), alert_history, and audit_log are ever
	// touched. Configuration (rule_sets, sensors, sites), accounts (users,
	// roles, sessions), and system_backups are never affected by this,
	// regardless of size pressure.
	DatabaseRetention struct {
		Enabled bool
		// Interval is how often the retention sweep runs.
		Interval time.Duration `mapstructure:"interval"`
		// *Days are age-based cutoffs, one per category. A row older than
		// this (by its own last-activity timestamp, not creation) is
		// deleted on every sweep, regardless of database size.
		TelemetryDays int `mapstructure:"telemetry_days"`
		AlertsDays    int `mapstructure:"alerts_days"`
		AuditDays     int `mapstructure:"audit_days"`
		// MaxDatabaseSizeGB is a backstop independent of the *Days
		// cutoffs above: if the *combined size of only the tables this
		// system is allowed to touch* exceeds this after the age-based
		// pass, the oldest rows across those same tables are deleted
		// (regardless of age) until back at or under TargetDatabaseSizeGB.
		// Deliberately scoped to just those tables rather than the whole
		// database, so growth in something this system can't touch (a
		// large rule_sets or system_backups, say) never triggers deleting
		// telemetry/alerts/audit data that isn't actually the problem.
		MaxDatabaseSizeGB    int `mapstructure:"max_database_size_gb"`
		TargetDatabaseSizeGB int `mapstructure:"target_database_size_gb"`
		// DeleteBatchSize caps how many rows a single DELETE removes —
		// large deletes are chunked into batches this size (with a short
		// pause between) so a big backlog doesn't hold a long-running
		// transaction/lock or spike load in one shot.
		DeleteBatchSize int `mapstructure:"delete_batch_size"`
	} `mapstructure:"database_retention"`

	// Notifications sends an out-of-band ping (email and/or webhook) when
	// a new alert at or above MinSeverity is recorded — see
	// internal/central/notify.go. Deliberately separate from SIEM export:
	// this is for "someone should look at this now," not a compliance
	// trail. Email is off by default even when Notifications.Enabled is
	// true — it needs real SMTP credentials to do anything useful, and
	// shipping with it silently active would mean a fresh install
	// occasionally tries (and fails) to send mail through unconfigured
	// settings. Webhook has no such prerequisite, so it's controlled
	// solely by its own Enabled flag.
	Notifications struct {
		Enabled     bool   `mapstructure:"enabled"`
		MinSeverity string `mapstructure:"min_severity"` // low|medium|high|critical
		Email       struct {
			Enabled  bool     `mapstructure:"enabled"`
			SMTPHost string   `mapstructure:"smtp_host"`
			SMTPPort int      `mapstructure:"smtp_port"`
			Username string   `mapstructure:"username"`
			Password string   `mapstructure:"password"`
			From     string   `mapstructure:"from"`
			To       []string `mapstructure:"to"`
			UseTLS   bool     `mapstructure:"use_tls"`
		} `mapstructure:"email"`
		Webhook struct {
			Enabled bool              `mapstructure:"enabled"`
			URL     string            `mapstructure:"url"`
			Headers map[string]string `mapstructure:"headers"`
		} `mapstructure:"webhook"`
	} `mapstructure:"notifications"`

	// Reports generates a periodic summary (new assets, alert counts by
	// severity, new incidents, topology growth, offline sensors) — see
	// internal/central/reports.go. Off by default. Uses
	// Notifications.Email's SMTP connection settings (host/port/user/
	// password/from/TLS) rather than duplicating them — Recipients here
	// is deliberately separate from Notifications.Email.To, since a
	// weekly management summary and a real-time alert ping often go to
	// different people. Every generated report is also saved to
	// report_history and viewable from the Reports tab regardless of
	// whether email delivery is configured or succeeds.
	Reports struct {
		Enabled bool
		// Schedule is currently "weekly" only — DayOfWeek (monday..sunday)
		// and HourUTC (0-23) say when in that cycle.
		Schedule   string   `mapstructure:"schedule"`
		DayOfWeek  string   `mapstructure:"day_of_week"`
		HourUTC    int      `mapstructure:"hour_utc"`
		Recipients []string `mapstructure:"recipients"`
	} `mapstructure:"reports"`
}

func LoadCentral(path string) (*CentralConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("OTLENS_CENTRAL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("web.host", "0.0.0.0")
	v.SetDefault("web.port", 8443)
	v.SetDefault("web.tls.enabled", false)
	v.SetDefault("web.tls.certfile", "central-web.crt")
	v.SetDefault("web.tls.keyfile", "central-web.key")
	v.SetDefault("web.tls.minversion", "1.2")
	v.SetDefault("web.tls.ciphersuites", []string{})
	v.SetDefault("sensor_api.host", "0.0.0.0")
	v.SetDefault("sensor_api.port", 9443)
	v.SetDefault("sensor_api.tls.enabled", false)
	v.SetDefault("sensor_api.tls.certfile", "central-sensor-api.crt")
	v.SetDefault("sensor_api.tls.keyfile", "central-sensor-api.key")
	v.SetDefault("sensor_api.tls.minversion", "1.2")
	v.SetDefault("sensor_api.tls.ciphersuites", []string{})
	v.SetDefault("database.host", "127.0.0.1")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "otlens")
	v.SetDefault("database.user", "otlens")
	v.SetDefault("database.password", "change-me")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("auth.management_token", "")
	v.SetDefault("auth.sensor_token", "")
	v.SetDefault("auth.session_duration", 6*time.Hour)
	v.SetDefault("auth.bootstrap_username", "administrator")
	v.SetDefault("auth.bootstrap_password", "administrator")
	v.SetDefault("analysis.enabled", true)
	v.SetDefault("analysis.upload_directory", "./data/pcap-uploads")
	v.SetDefault("analysis.max_upload_size_mb", 2048)
	v.SetDefault("analysis.job_timeout", 2*time.Hour)
	v.SetDefault("analysis.retain_pcap", 24*time.Hour)
	v.SetDefault("analysis.allow_import", true)
	v.SetDefault("siem.enabled", false)
	v.SetDefault("siem.url", "")
	v.SetDefault("siem.export_alerts", true)
	v.SetDefault("siem.export_audit", true)
	v.SetDefault("siem.source", "otlens-central")
	v.SetDefault("siem.bearer_token", "")
	v.SetDefault("siem.timeout", 10*time.Second)
	v.SetDefault("siem.retry_interval", 15*time.Second)
	v.SetDefault("siem.batch_size", 100)
	v.SetDefault("siem.max_attempts", 0)
	v.SetDefault("siem.headers", map[string]string{})
	v.SetDefault("siem.tls.insecure_skip_verify", false)
	v.SetDefault("siem.tls.ca_cert_file", "")
	v.SetDefault("siem.tls.client_cert_file", "")
	v.SetDefault("siem.tls.client_key_file", "")
	v.SetDefault("siem.tls.server_name", "")
	v.SetDefault("sensors.offline_after", 90*time.Second)
	v.SetDefault("sensors.check_interval", 20*time.Second)
	v.SetDefault("vulnerability.enabled", false)
	v.SetDefault("vulnerability.csv_path", "")
	v.SetDefault("database_retention.enabled", true)
	v.SetDefault("database_retention.interval", 6*time.Hour)
	v.SetDefault("database_retention.telemetry_days", 30)
	v.SetDefault("database_retention.alerts_days", 180)
	v.SetDefault("database_retention.audit_days", 365)
	v.SetDefault("database_retention.max_database_size_gb", 80)
	v.SetDefault("database_retention.target_database_size_gb", 70)
	v.SetDefault("database_retention.delete_batch_size", 10000)
	v.SetDefault("notifications.enabled", false)
	v.SetDefault("notifications.min_severity", "high")
	v.SetDefault("notifications.email.enabled", false)
	v.SetDefault("notifications.email.smtp_port", 587)
	v.SetDefault("notifications.email.use_tls", true)
	v.SetDefault("notifications.webhook.enabled", false)
	v.SetDefault("reports.enabled", false)
	v.SetDefault("reports.schedule", "weekly")
	v.SetDefault("reports.day_of_week", "monday")
	v.SetDefault("reports.hour_utc", 8)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("central config load failed: %w", err)
	}
	var cfg CentralConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("central config parse failed: %w", err)
	}
	if cfg.Database.Host == "" || cfg.Database.Name == "" || cfg.Database.User == "" {
		return nil, fmt.Errorf("central database host, name and user must be configured")
	}
	if cfg.SIEM.Enabled {
		u, err := url.Parse(strings.TrimSpace(cfg.SIEM.URL))
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("siem.url must be an absolute http(s) URL when siem.enabled is true")
		}
	}
	if cfg.SIEM.BatchSize <= 0 {
		cfg.SIEM.BatchSize = 100
	}
	if cfg.SIEM.Timeout <= 0 {
		cfg.SIEM.Timeout = 10 * time.Second
	}
	if cfg.SIEM.RetryInterval <= 0 {
		cfg.SIEM.RetryInterval = 15 * time.Second
	}
	if cfg.Notifications.Enabled {
		validSeverity := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		if !validSeverity[strings.ToLower(strings.TrimSpace(cfg.Notifications.MinSeverity))] {
			return nil, fmt.Errorf("notifications.min_severity must be low, medium, high, or critical")
		}
		if cfg.Notifications.Email.Enabled {
			if strings.TrimSpace(cfg.Notifications.Email.SMTPHost) == "" || strings.TrimSpace(cfg.Notifications.Email.From) == "" || len(cfg.Notifications.Email.To) == 0 {
				return nil, fmt.Errorf("notifications.email smtp_host, from, and to are required when email notifications are enabled")
			}
			if cfg.Notifications.Email.SMTPPort <= 0 || cfg.Notifications.Email.SMTPPort > 65535 {
				return nil, fmt.Errorf("notifications.email.smtp_port must be between 1 and 65535")
			}
		}
		if cfg.Notifications.Webhook.Enabled {
			u, err := url.Parse(strings.TrimSpace(cfg.Notifications.Webhook.URL))
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return nil, fmt.Errorf("notifications.webhook.url must be an absolute http(s) URL")
			}
		}
	}
	if cfg.Reports.Enabled {
		if !strings.EqualFold(strings.TrimSpace(cfg.Reports.Schedule), "weekly") {
			return nil, fmt.Errorf("reports.schedule must be weekly when reports.enabled is true")
		}
		validWeekday := map[string]bool{
			"sunday": true, "monday": true, "tuesday": true, "wednesday": true,
			"thursday": true, "friday": true, "saturday": true,
		}
		if !validWeekday[strings.ToLower(strings.TrimSpace(cfg.Reports.DayOfWeek))] {
			return nil, fmt.Errorf("reports.day_of_week must be sunday through saturday")
		}
		if cfg.Reports.HourUTC < 0 || cfg.Reports.HourUTC > 23 {
			return nil, fmt.Errorf("reports.hour_utc must be between 0 and 23")
		}
		if len(cfg.Reports.Recipients) > 0 {
			if strings.TrimSpace(cfg.Notifications.Email.SMTPHost) == "" || strings.TrimSpace(cfg.Notifications.Email.From) == "" {
				return nil, fmt.Errorf("reports.recipients requires notifications.email.smtp_host and notifications.email.from")
			}
			if cfg.Notifications.Email.SMTPPort <= 0 || cfg.Notifications.Email.SMTPPort > 65535 {
				return nil, fmt.Errorf("notifications.email.smtp_port must be between 1 and 65535 when reports have recipients")
			}
		}
	}
	return &cfg, nil
}

func Load(path string) (*Config, error) {

	viper.SetConfigFile(path)

	// Lets any setting be overridden by an OTLENS_-prefixed
	// environment variable without touching config.yaml. This is
	// especially useful for deployment-specific values and secrets
	// such as the Central sensor token.
	viper.SetEnvPrefix("OTLENS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("debug.enabled", false)
	viper.SetDefault("central.enabled", false)
	viper.SetDefault("central.url", "")
	viper.SetDefault("central.sensor_id", "")
	viper.SetDefault("central.name", "")
	viper.SetDefault("central.site_id", "")
	viper.SetDefault("central.token", "")
	viper.SetDefault("central.credential_file", "")
	viper.SetDefault("central.interval", 30*time.Second)
	viper.SetDefault("central.timeout", 15*time.Second)
	viper.SetDefault("central.insecure_skip_verify", false)

	viper.SetDefault("capture.mode", "pcap")
	viper.SetDefault("capture.snaplen", 1600)
	viper.SetDefault("capture.promiscuous", true)
	viper.SetDefault("capture.bpffilter", "")
	viper.SetDefault("capture.ipfix.listenaddr", "0.0.0.0:4739")
	viper.SetDefault("capture.tcp_reassembly.enabled", true)
	viper.SetDefault("capture.tcp_reassembly.max_connections", 50000)
	viper.SetDefault("capture.tcp_reassembly.max_buffer_per_direction", 4194304)
	viper.SetDefault("capture.tcp_reassembly.max_total_buffer", 536870912)
	viper.SetDefault("capture.tcp_reassembly.idle_timeout", 2*time.Minute)
	viper.SetDefault("capture.tcp_reassembly.closed_timeout", 15*time.Second)
	viper.SetDefault("capture.tcp_reassembly.max_out_of_order_segments", 256)
	viper.SetDefault("capture.tcp_reassembly.max_sequence_gap", 16777216)
	viper.SetDefault("capture.tcp_reassembly.gap_recovery_timeout", 2*time.Second)
	viper.SetDefault("capture.tcp_reassembly.shard_count", 32)
	viper.SetDefault("capture.tcp_reassembly.overlap_policy", "first_seen")
	viper.SetDefault("capture.udp_conversations.max_active", 100000)
	viper.SetDefault("capture.udp_conversations.enabled", true)
	viper.SetDefault("capture.udp_conversations.max_packets_per_conversation", 100000)
	viper.SetDefault("capture.udp_conversations.max_pending_requests_per_conversation", 256)
	viper.SetDefault("capture.udp_conversations.idle_timeout", 30*time.Second)
	viper.SetDefault("capture.udp_conversations.retain_payload", false)
	viper.SetDefault("capture.udp_conversations.protocols.dns.timeout", 5*time.Second)
	viper.SetDefault("capture.udp_conversations.protocols.dhcp.timeout", 60*time.Second)
	viper.SetDefault("capture.udp_conversations.protocols.snmp.timeout", 10*time.Second)
	viper.SetDefault("capture.udp_conversations.protocols.sip.timeout", 5*time.Minute)

	viper.SetDefault("ics.modbusport", 502)
	viper.SetDefault("ics.s7port", 102)
	viper.SetDefault("ics.ethernetipport", 44818)
	viper.SetDefault("ics.dnp3port", 20000)
	viper.SetDefault("ics.opcuaport", 4840)
	viper.SetDefault("ics.bacnetport", 47808)
	viper.SetDefault("ics.iec104port", 2404)

	viper.SetDefault("baseline.enabled", true)
	viper.SetDefault("baseline.learningduration", time.Hour)
	viper.SetDefault("baseline.behaviorenabled", true)
	viper.SetDefault("baseline.bucketduration", time.Hour)
	viper.SetDefault("baseline.maxprofiles", 100000)
	viper.SetDefault("baseline.maxassetprofiles", 100000)
	viper.SetDefault("baseline.minassetsamples", 50)
	viper.SetDefault("baseline.minassetage", 5*time.Minute)
	viper.SetDefault("baseline.readinessthreshold", 0.85)
	viper.SetDefault("baseline.maxlearningmultiplier", 2.0)
	viper.SetDefault("baseline.candidateminsamples", 20)
	viper.SetDefault("baseline.candidatemindays", 3)
	viper.SetDefault("baseline.minstatsamples", 30)
	viper.SetDefault("baseline.maintenancewindows", []string{})
	viper.SetDefault("nba.enabled", true)
	viper.SetDefault("nba.minscore", 40.0)
	viper.SetDefault("nba.maxanomalies", 10000)
	viper.SetDefault("nba.cooldown", 5*time.Minute)
	viper.SetDefault("nba.riskenabled", true)
	viper.SetDefault("nba.maxassessments", 10000)
	viper.SetDefault("nba.correlationenabled", true)
	viper.SetDefault("nba.correlationwindow", 15*time.Minute)
	viper.SetDefault("nba.findingexpireafter", 30*time.Minute)
	viper.SetDefault("nba.maxfindings", 10000)
	viper.SetDefault("nba.maxassessmentsperfinding", 256)
	viper.SetDefault("nba.minfindingscore", 40.0)
	viper.SetDefault("nba.alertthreshold", 70.0)
	viper.SetDefault("nba.incidentthreshold", 85.0)

	viper.SetDefault("deception.honeypotthreshold", 100)

	viper.SetDefault("detect.arpconfirmthreshold", 3)
	viper.SetDefault("detect.segmentation.enabled", false)
	viper.SetDefault("detect.segmentation.maxleveljump", 1.0)
	viper.SetDefault("detect.reconnaissance.enabled", true)
	viper.SetDefault("detect.reconnaissance.window", 60*time.Second)
	viper.SetDefault("detect.reconnaissance.hostscanthreshold", 15)
	viper.SetDefault("detect.reconnaissance.portscanthreshold", 15)
	viper.SetDefault("detect.threatintel.enabled", false)
	viper.SetDefault("detect.threatintel.refreshinterval", time.Hour)
	viper.SetDefault("detect.threatintel.httptimeout", 15*time.Second)
	viper.SetDefault("detect.threatintel.maxdnsobservations", 5000)
	viper.SetDefault("detect.otvalueanomaly.enabled", true)
	viper.SetDefault("detect.otvalueanomaly.minsamples", 20)
	viper.SetDefault("detect.otvalueanomaly.zscorethreshold", 4.0)
	viper.SetDefault("detect.otvalueanomaly.ratemultiplier", 6.0)
	viper.SetDefault("detect.otvalueanomaly.stuckafter", 30*time.Minute)
	viper.SetDefault("detect.otvalueanomaly.missingafter", 10*time.Minute)
	viper.SetDefault("detect.otvalueanomaly.togglewindow", 5*time.Minute)
	viper.SetDefault("detect.otvalueanomaly.togglethreshold", 10)
	viper.SetDefault("detect.otvalueanomaly.unexpectedwrites", true)
	viper.SetDefault("detect.otvalueanomaly.checkinterval", time.Minute)
	viper.SetDefault("detect.lateralmovement.enabled", true)
	viper.SetDefault("detect.lateralmovement.window", 5*time.Minute)
	viper.SetDefault("detect.lateralmovement.fanoutthreshold", 5)
	viper.SetDefault("detect.lateralmovement.largetransferbytes", 104857600)
	viper.SetDefault("detect.lateralmovement.pivotwindow", 10*time.Minute)
	viper.SetDefault("detect.lateralmovement.adminports", []uint16{22, 135, 139, 445, 3389, 5985, 5986})
	viper.SetDefault("detect.c2correlation.enabled", true)
	viper.SetDefault("detect.c2correlation.minscore", 60)
	viper.SetDefault("detect.c2correlation.dnswindow", 10*time.Minute)
	viper.SetDefault("detect.c2correlation.nxdomainthreshold", 20)
	viper.SetDefault("detect.c2correlation.uniquesubdomainthreshold", 20)
	viper.SetDefault("detect.c2correlation.longlabellength", 45)
	viper.SetDefault("detect.c2beacon.enabled", true)
	viper.SetDefault("detect.c2beacon.minsamples", 6)
	viper.SetDefault("detect.c2beacon.maxcoefficientofvariation", 0.15)
	viper.SetDefault("detect.c2beacon.mininterval", 5*time.Second)
	viper.SetDefault("detect.c2beacon.maxinterval", time.Hour)
	viper.SetDefault("detect.c2beacon.maxtrackeddestinations", 5000)

	viper.SetDefault("store.maxvaluechanges", 1000)
	viper.SetDefault("store.maxcontrolevents", 1000)

	viper.SetDefault("persist.path", "otlens.db")
	viper.SetDefault("persist.flushinterval", 10*time.Second)
	viper.SetDefault("persist.retention", 7*24*time.Hour)

	viper.SetDefault("oui.csvpath", "")

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.output", []string{"stderr"})

	viper.SetDefault("logging.rotation.enabled", false)
	viper.SetDefault("logging.rotation.maxsizemb", 100)
	viper.SetDefault("logging.rotation.maxbackups", 10)
	viper.SetDefault("logging.rotation.maxagedays", 90)
	viper.SetDefault("logging.rotation.compress", true)

	err := viper.ReadInConfig()

	if err != nil {
		return nil, fmt.Errorf("config load failed: %w", err)
	}

	var cfg Config

	err = viper.Unmarshal(&cfg)

	if err != nil {
		return nil, err
	}

	// Read the nested reassembly switch directly as well. Older deployments and
	// some mapstructure versions could leave this nested bool at its zero value
	// even though Viper had the configured/default value.
	cfg.Capture.TCPReassembly.Enabled = viper.GetBool("capture.tcp_reassembly.enabled")

	if cfg.Central.Enabled {
		if strings.TrimSpace(cfg.Central.URL) == "" {
			return nil, fmt.Errorf("central.url must not be empty when central.enabled is true")
		}
		if strings.TrimSpace(cfg.Central.SensorID) == "" {
			return nil, fmt.Errorf("central.sensor_id must not be empty when central.enabled is true")
		}
		if strings.TrimSpace(cfg.Central.Token) == "" {
			return nil, fmt.Errorf("central.token must not be empty when central.enabled is true")
		}
		if !strings.HasPrefix(cfg.Central.URL, "http://") && !strings.HasPrefix(cfg.Central.URL, "https://") {
			return nil, fmt.Errorf("central.url must start with http:// or https://")
		}
	}

	if cfg.Deception.HoneypotThreshold < 0 || cfg.Deception.HoneypotThreshold > 100 {
		return nil, fmt.Errorf("deception.honeypotthreshold must be between 0 and 100, got %d", cfg.Deception.HoneypotThreshold)
	}

	if cfg.Detect.Segmentation.MaxLevelJump <= 0 || cfg.Detect.Segmentation.MaxLevelJump > 5 {
		return nil, fmt.Errorf("detect.segmentation.maxleveljump must be > 0 and <= 5, got %.3g", cfg.Detect.Segmentation.MaxLevelJump)
	}
	validPurdue := func(level float64) bool {
		switch level {
		case 0, 1, 2, 3, 3.5, 4, 5:
			return true
		default:
			return false
		}
	}
	for vlan, level := range cfg.Detect.Segmentation.VLANLevels {
		if vlan > 4094 {
			return nil, fmt.Errorf("detect.segmentation.vlanlevels contains invalid VLAN %d; expected 0-4094", vlan)
		}
		if !validPurdue(level) {
			return nil, fmt.Errorf("detect.segmentation.vlanlevels[%d] has invalid Purdue level %.3g; allowed levels are 0, 1, 2, 3, 3.5, 4, 5", vlan, level)
		}
	}

	seenDeceptionIPs := make(map[string]struct{}, len(cfg.Deception.Stations))
	for i, station := range cfg.Deception.Stations {
		if station.IP == "" {
			return nil, fmt.Errorf("deception.stations[%d].ip must not be empty", i)
		}
		if station.Score < 0 || station.Score > 100 {
			return nil, fmt.Errorf("deception.stations[%d].score must be between 0 and 100, got %d", i, station.Score)
		}
		if _, exists := seenDeceptionIPs[station.IP]; exists {
			return nil, fmt.Errorf("deception.stations contains duplicate IP %q", station.IP)
		}
		seenDeceptionIPs[station.IP] = struct{}{}
	}

	return &cfg, nil
}
