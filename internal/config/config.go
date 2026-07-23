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

	// Export forwards each alert, as it's raised, to an external
	// server as JSON over HTTPS — see internal/export. Off by
	// default; entirely optional.
	Export struct {
		Enabled bool

		// URL the alert JSON is POSTed to. Should be an https:// URL
		// — TLS is what actually secures this in transit; pointing
		// this at a plain http:// URL sends alert data unencrypted,
		// which defeats the point of this feature for anything
		// beyond local testing.
		URL string

		TLS struct {
			// InsecureSkipVerify disables TLS certificate validation
			// for the export server — only for a self-signed/
			// internal server during setup or testing. Leave false
			// for anything that matters; prefer CACertFile (trust
			// one specific CA) over this (trust anything) whenever
			// the export server's certificate isn't from a public
			// CA.
			InsecureSkipVerify bool

			// CACertFile, if set, is a PEM-encoded CA certificate to
			// trust for the export server, in addition to the
			// system's normal CA pool.
			CACertFile string
		}

		// Timeout bounds each individual export HTTP request. Go
		// duration syntax, e.g. "10s".
		Timeout time.Duration
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
		ModbusPort uint16
		S7Port     uint16
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

	API struct {
		Host string
		Port int

		// Mode is gin's run mode: "debug" or "release" ("test" also
		// accepted but not typically used outside gin's own tests).
		// "release" turns off gin's per-request debug logging and
		// warnings — appropriate once you're done developing against
		// the API.
		Mode string

		// CORSOrigin is the Access-Control-Allow-Origin value sent
		// on every API response, so a browser-based dashboard on a
		// different origin/port can call it. Empty (the default)
		// sends no CORS header at all — only same-origin requests
		// work, which is what the bundled dashboard needs since it's
		// served from this same process. Set this to a specific
		// origin only if something else genuinely needs cross-origin
		// access; avoid "*" (any origin) outside of local/development
		// use — see api.username/password below for why that matters
		// more here than on a typical API.
		CORSOrigin string

		// Username/Password, if both set, require HTTP Basic Auth on
		// every request except /health. Leave both empty (the
		// default) to run unauthenticated — appropriate only when
		// this is reachable exclusively from an already-trusted
		// network. Prefer setting Password via the
		// OTLENS_API_PASSWORD environment variable (see
		// Load/AutomaticEnv) over writing it in config.yaml in
		// plaintext.
		Username string
		Password string

		// TLS controls whether the API is served over HTTPS. The API
		// is unencrypted (plain HTTP) by default — set Enabled: true
		// to turn on TLS; everything else here has a sensible
		// default so enabling it can be as simple as flipping that
		// one flag. See internal/api/tls.go.
		TLS struct {
			Enabled bool

			// CertFile/KeyFile: if both already exist, they're used
			// as-is (bring your own CA-signed certificate here). If
			// either is missing, OTLens generates a self-signed pair
			// at these paths automatically on startup.
			CertFile string
			KeyFile  string

			// MinVersion: "1.0", "1.1", "1.2", or "1.3". Defaults to
			// "1.2" if empty.
			MinVersion string

			// CipherSuites: Go/IANA cipher suite names (see
			// `go doc crypto/tls.CipherSuites`), e.g.
			// ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]. Empty means
			// "use Go's own secure defaults". Only takes effect when
			// the connection negotiates TLS 1.2 or below — TLS 1.3's
			// suites are fixed by the protocol itself.
			CipherSuites []string
		}
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

	// Vulnerability looks up known vulnerabilities for a device's
	// vendor — see internal/vuln's package doc comment for why this
	// is offline-only by design (a local snapshot file, prepared out
	// of band and carried in — never a live network call), not just
	// an offline fallback for when a live lookup isn't reachable.
	Vulnerability struct {
		Enabled bool

		// DataPath is the local snapshot CSV — see vuln.Database.
		// LoadCSV for the expected column format, and
		// DOCUMENTATION.md for how to prepare one from CISA's public
		// ICS Advisories feed.
		DataPath string
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

	// Audit controls a separate, low-volume, high-importance trail of
	// who did what — admin actions (wipe, capture control, alert
	// review, asset confirm/delete), and failed authentication
	// attempts — distinct from the routine application log (Logging
	// above). See internal/audit.
	Audit struct {
		Enabled bool

		// Path is the audit log file — always a file, unlike
		// Logging.Output there's no "stdout"/"stderr" option, since
		// an audit trail belongs in a durable file, not transient
		// console output. Rotated using Logging.Rotation's settings.
		Path string
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
	// environment variable without touching config.yaml — e.g.
	// OTLENS_API_PASSWORD overrides api.password. Mainly so a secret
	// like api.password doesn't have to sit in plaintext in the
	// config file at all; every other setting can still just live in
	// config.yaml as normal.
	viper.SetEnvPrefix("OTLENS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("debug.enabled", false)
	viper.SetDefault("export.enabled", false)
	viper.SetDefault("export.timeout", 10*time.Second)
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

	viper.SetDefault("baseline.enabled", true)
	viper.SetDefault("baseline.learningduration", time.Hour)

	viper.SetDefault("deception.honeypotthreshold", 100)

	viper.SetDefault("detect.arpconfirmthreshold", 3)

	viper.SetDefault("store.maxvaluechanges", 1000)
	viper.SetDefault("store.maxcontrolevents", 1000)

	viper.SetDefault("persist.path", "otlens.db")
	viper.SetDefault("persist.flushinterval", 10*time.Second)
	viper.SetDefault("persist.retention", 7*24*time.Hour)

	viper.SetDefault("api.mode", "debug")

	// Empty by default — no Access-Control-Allow-Origin header at
	// all, so only same-origin requests (the dashboard itself,
	// served from this same process under /ui) work out of the box.
	// A wildcard "*" here would let any website in a visiting
	// browser make requests to this API and read the response —
	// combined with there being no authentication unless
	// api.username/password are set below, that's a real data-
	// exfiltration path, not just a theoretical one. Set this to a
	// specific origin only if something genuinely needs cross-origin
	// access.
	viper.SetDefault("api.corsorigin", "")

	// Empty by default — no HTTP Basic Auth. Set both api.username
	// and api.password (or their OTLENS_API_USERNAME/
	// OTLENS_API_PASSWORD environment variable equivalents — see
	// AutomaticEnv above) to require credentials for everything
	// except /health. Setting only one of the two is treated as a
	// config error at startup (see Validate) rather than silently
	// leaving the API unauthenticated.
	viper.SetDefault("api.username", "")
	viper.SetDefault("api.password", "")

	viper.SetDefault("api.tls.enabled", false)
	viper.SetDefault("api.tls.certfile", "otlens.crt")
	viper.SetDefault("api.tls.keyfile", "otlens.key")
	viper.SetDefault("api.tls.minversion", "1.2")
	viper.SetDefault("api.tls.ciphersuites", []string{})

	viper.SetDefault("oui.csvpath", "")

	viper.SetDefault("vulnerability.enabled", false)
	viper.SetDefault("vulnerability.datapath", "ics_advisories.csv")

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.output", []string{"stderr"})

	viper.SetDefault("logging.rotation.enabled", false)
	viper.SetDefault("logging.rotation.maxsizemb", 100)
	viper.SetDefault("logging.rotation.maxbackups", 10)
	viper.SetDefault("logging.rotation.maxagedays", 90)
	viper.SetDefault("logging.rotation.compress", true)

	viper.SetDefault("audit.enabled", false)
	viper.SetDefault("audit.path", "audit.log")

	err := viper.ReadInConfig()

	if err != nil {
		return nil, fmt.Errorf("config load failed: %w", err)
	}

	var cfg Config

	err = viper.Unmarshal(&cfg)

	if err != nil {
		return nil, err
	}

	if (cfg.API.Username == "") != (cfg.API.Password == "") {
		return nil, fmt.Errorf(
			"api.username and api.password must both be set to enable Basic Auth, or both left empty to run unauthenticated — only one is currently set",
		)
	}

	return &cfg, nil
}
