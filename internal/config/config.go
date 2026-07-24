// Package config loads and validates configs/sensor.config.example.yaml (via
// viper) into a single Config struct that internal/app then threads
// out to every engine's constructor. This is the one place default
// values are defined — see Load's viper.SetDefault calls — so a
// setting can be safely omitted from config.yaml entirely and still
// behave sensibly.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

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
		// How many consecutive conflicting ARP claims for the same
		// IP are required before treating the new MAC as legitimate
		// (debounces against a single stray/retransmitted packet).
		ARPConfirmThreshold int
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
	if cfg.SIEM.Enabled && strings.TrimSpace(cfg.SIEM.URL) == "" {
		return nil, fmt.Errorf("siem.url must be configured when siem.enabled is true")
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
	viper.SetDefault("central.interval", 30*time.Second)
	viper.SetDefault("central.timeout", 15*time.Second)
	viper.SetDefault("central.insecure_skip_verify", false)

	viper.SetDefault("capture.mode", "pcap")
	viper.SetDefault("capture.snaplen", 1600)
	viper.SetDefault("capture.promiscuous", true)
	viper.SetDefault("capture.bpffilter", "")
	viper.SetDefault("capture.ipfix.listenaddr", "0.0.0.0:4739")

	viper.SetDefault("ics.modbusport", 502)
	viper.SetDefault("ics.s7port", 102)
	viper.SetDefault("ics.ethernetipport", 44818)
	viper.SetDefault("ics.dnp3port", 20000)
	viper.SetDefault("ics.opcuaport", 4840)
	viper.SetDefault("ics.bacnetport", 47808)
	viper.SetDefault("ics.iec104port", 2404)

	viper.SetDefault("baseline.enabled", true)
	viper.SetDefault("baseline.learningduration", time.Hour)

	viper.SetDefault("deception.honeypotthreshold", 100)

	viper.SetDefault("detect.arpconfirmthreshold", 3)

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
