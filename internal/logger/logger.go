// Package logger provides the single global structured logger
// (zap, JSON) every other package logs through — call Init once at
// startup before anything else runs, and Sync before the process
// exits so buffered log lines aren't lost.
package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.Logger

// Init builds the global logger at the given level — accepts the
// same level names zap itself uses ("debug", "info", "warn",
// "error"...). An unrecognized level falls back to "info" rather
// than failing startup over a config typo.
//
// outputs is where log lines are written — any combination of
// "stdout", "stderr", or a file path (e.g. "otlens.log"); the file
// is created if it doesn't exist and appended to if it does. An
// empty outputs falls back to ["stderr"], matching the original
// console-only behavior, so this is safe to leave unset in
// config.yaml.
//
// rotation controls in-process log file rotation for any file-path
// outputs (stdout/stderr are never rotated — rotation only makes
// sense for an actual file) — see RotationConfig's doc comment for
// why this exists as a small hand-rolled mechanism rather than an
// external dependency. Pass a zero-value RotationConfig (Enabled:
// false) to keep the previous unbounded-growth behavior.
func Init(level string, outputs []string, rotation RotationConfig) error {

	var zapLevel zapcore.Level

	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	if len(outputs) == 0 {
		outputs = []string{"stderr"}
	}

	writer, err := buildWriteSyncer(outputs, rotation)

	if err != nil {
		return fmt.Errorf("building logger (outputs=%v) failed: %w", outputs, err)
	}

	Log = zap.New(zapcore.NewCore(jsonEncoder(), writer, zap.NewAtomicLevelAt(zapLevel)))

	return nil
}

// NewAudit builds a separate, independent zap logger for structured
// audit entries (see internal/audit) — deliberately not the same
// logger as Log/Init's main application logger: audit entries are
// low-volume, high-importance records (who did what, when) that
// belong in their own file with their own retention, not interleaved
// with routine debug/info application log lines. Uses the same
// rotation semantics/config shape as Init.
func NewAudit(path string, rotation RotationConfig) (*zap.Logger, error) {

	writer, err := buildWriteSyncer([]string{path}, rotation)

	if err != nil {
		return nil, fmt.Errorf("building audit logger (path=%q) failed: %w", path, err)
	}

	// Always Info level — an audit logger doesn't have a "too
	// verbose, turn it down" use case the way the main app logger
	// does; every entry written to it is, by construction, something
	// that was already decided to be audit-worthy before it got here.
	return zap.New(zapcore.NewCore(jsonEncoder(), writer, zap.NewAtomicLevelAt(zapcore.InfoLevel))), nil
}

func jsonEncoder() zapcore.Encoder {

	cfg := zap.NewProductionEncoderConfig()
	cfg.TimeKey = "ts"
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder

	return zapcore.NewJSONEncoder(cfg)
}

// buildWriteSyncer combines all configured outputs (stdout/stderr/
// file paths) into one zapcore.WriteSyncer. A file path output gets
// wrapped in a RotatingWriter when rotation.Enabled — see
// RotationConfig — so it doesn't grow without bound; otherwise it's
// a plain append-only file, same as before rotation support existed.
func buildWriteSyncer(outputs []string, rotation RotationConfig) (zapcore.WriteSyncer, error) {

	syncers := make([]zapcore.WriteSyncer, 0, len(outputs))

	for _, output := range outputs {

		switch output {

		case "stdout":
			syncers = append(syncers, zapcore.AddSync(os.Stdout))

		case "stderr":
			syncers = append(syncers, zapcore.AddSync(os.Stderr))

		default:

			if rotation.Enabled {

				rw, err := NewRotatingWriter(output, rotation)

				if err != nil {
					return nil, err
				}

				syncers = append(syncers, zapcore.AddSync(rw))

			} else {

				file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)

				if err != nil {
					return nil, fmt.Errorf("opening log file %q failed: %w", output, err)
				}

				syncers = append(syncers, zapcore.AddSync(file))
			}
		}
	}

	return zapcore.NewMultiWriteSyncer(syncers...), nil
}

func Sync() {

	if Log != nil {
		Log.Sync()
	}

}
