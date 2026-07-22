package logger

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RotationConfig controls in-process log file rotation — used both
// by the main application log (logging.rotation in config.yaml) and
// the audit log (internal/audit's NewAudit), so both share the exact
// same rotation semantics and config shape.
//
// This is a small hand-rolled implementation rather than a
// dependency like lumberjack, specifically so adding rotation didn't
// require a new go.mod entry — same "small, focused, standard-
// library-only where reasonable" spirit as the rest of this
// codebase. The behavior (size-based rotation, a bounded number of
// kept backups, age-based cleanup, optional gzip) matches what
// lumberjack would do; swapping to that library later, if ever
// wanted, is a drop-in replacement — RotatingWriter and
// lumberjack.Logger both just implement io.Writer.
type RotationConfig struct {
	Enabled bool

	MaxSizeMB  int  // rotate once the file reaches this size. 0 = never rotate by size.
	MaxBackups int  // keep at most this many rotated files. 0 = unlimited.
	MaxAgeDays int  // delete rotated files older than this. 0 = unlimited.
	Compress   bool // gzip rotated files
}

// RotatingWriter is an io.Writer that rotates the underlying file
// once it grows past Config.MaxSizeMB, keeping at most
// Config.MaxBackups old copies (further bounded by MaxAgeDays), each
// optionally gzip-compressed. Safe for concurrent use.
type RotatingWriter struct {
	path   string
	config RotationConfig

	mutex sync.Mutex
	file  *os.File
	size  int64
}

// NewRotatingWriter opens (creating if necessary) the log file at
// path, resuming its existing size so a restart doesn't immediately
// trigger a spurious rotation on the very next write.
func NewRotatingWriter(path string, config RotationConfig) (*RotatingWriter, error) {

	w := &RotatingWriter{
		path:   path,
		config: config,
	}

	if err := w.openExisting(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *RotatingWriter) openExisting() error {

	info, statErr := os.Stat(w.path)

	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}

	file, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)

	if err != nil {
		return fmt.Errorf("opening log file %q failed: %w", w.path, err)
	}

	w.file = file

	if statErr == nil {
		w.size = info.Size()
	}

	return nil
}

// Write implements io.Writer. Rotates first if this write would push
// the file past MaxSizeMB.
func (w *RotatingWriter) Write(p []byte) (int, error) {

	w.mutex.Lock()
	defer w.mutex.Unlock()

	maxSize := int64(w.config.MaxSizeMB) * 1024 * 1024

	if maxSize > 0 && w.size+int64(len(p)) > maxSize {

		if err := w.rotate(); err != nil {

			// Fall through and write anyway rather than losing the
			// log line entirely over a rotation failure (e.g. a
			// transient permission issue) — better a too-large file
			// than a silently dropped audit/log entry.
			fmt.Fprintf(os.Stderr, "log rotation failed for %q: %v\n", w.path, err)
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)

	return n, err
}

// rotate closes the current file, renames it to a timestamped
// backup (optionally gzip-compressing it), enforces MaxBackups/
// MaxAgeDays, and opens a fresh file at the original path. Caller
// must hold w.mutex.
func (w *RotatingWriter) rotate() error {

	if w.file != nil {
		w.file.Close()
	}

	backupPath := fmt.Sprintf("%s.%s", w.path, time.Now().Format("20060102-150405"))

	if err := os.Rename(w.path, backupPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if w.config.Compress {

		if err := compressFile(backupPath); err != nil {

			fmt.Fprintf(os.Stderr, "compressing rotated log %q failed: %v\n", backupPath, err)
		}
	}

	w.enforceRetention()

	file, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)

	if err != nil {
		return err
	}

	w.file = file
	w.size = 0

	return nil
}

// compressFile gzips path to path+".gz" and removes the original —
// best-effort; a failure here just leaves the uncompressed backup in
// place, still counted normally by enforceRetention.
func compressFile(path string) error {

	data, err := os.ReadFile(path)

	if err != nil {
		return err
	}

	out, err := os.Create(path + ".gz")

	if err != nil {
		return err
	}

	defer out.Close()

	gz := gzip.NewWriter(out)

	if _, err := gz.Write(data); err != nil {
		gz.Close()
		return err
	}

	if err := gz.Close(); err != nil {
		return err
	}

	return os.Remove(path)
}

// enforceRetention deletes old backup files beyond MaxBackups (by
// count, oldest first) and beyond MaxAgeDays (by modification time).
// Caller must hold w.mutex.
func (w *RotatingWriter) enforceRetention() {

	if w.config.MaxBackups <= 0 && w.config.MaxAgeDays <= 0 {
		return
	}

	dir := filepath.Dir(w.path)
	base := filepath.Base(w.path)

	entries, err := os.ReadDir(dir)

	if err != nil {
		return
	}

	type backupFile struct {
		path    string
		modTime time.Time
	}

	var backups []backupFile

	for _, entry := range entries {

		name := entry.Name()

		// Rotated files are named "<base>.<timestamp>" or
		// "<base>.<timestamp>.gz" — anything with base+"." as a
		// prefix that isn't the live file itself.
		if entry.IsDir() || name == base || !strings.HasPrefix(name, base+".") {
			continue
		}

		info, err := entry.Info()

		if err != nil {
			continue
		}

		backups = append(backups, backupFile{
			path:    filepath.Join(dir, name),
			modTime: info.ModTime(),
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.Before(backups[j].modTime)
	})

	now := time.Now()
	keepFromIndex := 0

	if w.config.MaxBackups > 0 && len(backups) > w.config.MaxBackups {
		keepFromIndex = len(backups) - w.config.MaxBackups
	}

	for i, b := range backups {

		tooMany := i < keepFromIndex

		tooOld := w.config.MaxAgeDays > 0 &&
			now.Sub(b.modTime) > time.Duration(w.config.MaxAgeDays)*24*time.Hour

		if tooMany || tooOld {
			os.Remove(b.path)
		}
	}
}
