// Package audit writes a durable, low-volume trail of who did what
// through the API — admin/state-changing actions and failed
// authentication attempts — distinct from internal/logger's routine
// application log. See core.EventAuditAction's doc comment for the
// full list of what gets recorded and where the entries come from.
package audit

import (
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

// Engine writes core.AuditEntry events to a rotated audit log file.
//
// A zero-value Engine (log == nil, as returned by New when audit.
// enabled is false) is a working no-op: Start still subscribes and
// runs its goroutine, it just discards everything received instead
// of writing it. This means every caller can unconditionally
// construct and Start an Engine without a separate "audit disabled"
// branch of their own — internal/app.go doesn't need to know or care
// whether audit logging is actually on.
type Engine struct {
	log *zap.Logger
}

// New builds an audit Engine. rotation is shared with
// config.Logging.Rotation — see logger.RotationConfig's doc comment
// for why the audit log and the main application log use the exact
// same rotation mechanism/config shape.
func New(enabled bool, path string, rotation logger.RotationConfig) (*Engine, error) {

	if !enabled {
		return &Engine{}, nil
	}

	log, err := logger.NewAudit(path, rotation)

	if err != nil {
		return nil, err
	}

	return &Engine{log: log}, nil
}

// Start subscribes to core.EventAuditAction and writes each entry to
// the audit log as it arrives.
func (e *Engine) Start(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventAuditAction)

	go func() {

		for event := range ch {

			entry, ok := event.Data.(core.AuditEntry)

			if !ok {
				continue
			}

			e.write(entry)

		}

	}()

}

func (e *Engine) write(entry core.AuditEntry) {

	if e.log == nil {
		return
	}

	fields := make([]zap.Field, 0, len(entry.Details)+4)

	fields = append(fields,
		zap.Time("action_ts", entry.Timestamp),
		zap.String("source_ip", entry.SourceIP),
		zap.String("user", entry.User),
		zap.Bool("success", entry.Success),
	)

	for k, v := range entry.Details {
		fields = append(fields, zap.String(k, v))
	}

	e.log.Info(entry.Action, fields...)
}
