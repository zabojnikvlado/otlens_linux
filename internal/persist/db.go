package persist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	_ "modernc.org/sqlite"
)

// DB is the local persistent store used by an OTLens sensor. Runtime
// persistence is SQLite so the sensor can run on Linux without a separate
// database service. Data is stored as JSON blobs behind a small keyed KV
// abstraction; the application-facing persistence API remains unchanged.
type DB struct {
	sql  *sql.DB
	path string
}

const sqliteBusyTimeout = 5000

func Open(path string) (*DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite database path is empty")
	}

	if dir := strings.TrimSpace(path); dir != "" {
		if parent := dirName(path); parent != "." && parent != "" {
			if err := os.MkdirAll(parent, 0750); err != nil {
				return nil, fmt.Errorf("creating sqlite database directory %q: %w", parent, err)
			}
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db %q: %w", path, err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	pragmas := []string{
		fmt.Sprintf("PRAGMA busy_timeout = %d", sqliteBusyTimeout),
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initializing sqlite db %q: %w", path, err)
		}
	}

	if _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS kv (
            bucket TEXT NOT NULL,
            key TEXT NOT NULL,
            value BLOB NOT NULL,
            PRIMARY KEY (bucket, key)
        ) WITHOUT ROWID;
    `); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating sqlite schema: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("checking sqlite db %q: %w", path, err)
	}

	return &DB{sql: db, path: path}, nil
}

func dirName(path string) string {
	idx := strings.LastIndexAny(path, `/\\`)
	if idx < 0 {
		return "."
	}
	if idx == 0 {
		return path[:1]
	}
	return path[:idx]
}

func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

func (d *DB) EnsureBucket(name string) error {
	// Buckets are logical namespaces in the SQLite kv table. Nothing needs
	// to be created, but validating the name here keeps the old API's
	// startup semantics and prevents accidental empty namespaces.
	if strings.TrimSpace(name) == "" {
		return errors.New("sqlite bucket name is empty")
	}
	return nil
}

func syncKeyed[T any](d *DB, bucket string, items []T, keyFn func(T) string) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM kv WHERE bucket = ?`, bucket); err != nil {
		return fmt.Errorf("clearing sqlite bucket %q: %w", bucket, err)
	}

	stmt, err := tx.Prepare(`INSERT INTO kv(bucket, key, value) VALUES(?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing sqlite insert: %w", err)
	}
	defer stmt.Close()

	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("marshal failed: %w", err)
		}
		if _, err := stmt.Exec(bucket, keyFn(item), data); err != nil {
			return fmt.Errorf("writing sqlite bucket %q: %w", bucket, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing sqlite transaction: %w", err)
	}
	return nil
}

func loadKeyed[T any](d *DB, bucket string) ([]T, error) {
	rows, err := d.sql.Query(`SELECT value FROM kv WHERE bucket = ? ORDER BY key`, bucket)
	if err != nil {
		return nil, fmt.Errorf("reading sqlite bucket %q: %w", bucket, err)
	}
	defer rows.Close()

	var result []T
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("reading sqlite value: %w", err)
		}
		var item T
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating sqlite bucket %q: %w", bucket, err)
	}
	return result, nil
}

func saveBlob(d *DB, bucket, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}
	_, err = d.sql.Exec(`INSERT INTO kv(bucket, key, value) VALUES(?, ?, ?) ON CONFLICT(bucket, key) DO UPDATE SET value = excluded.value`, bucket, key, data)
	if err != nil {
		return fmt.Errorf("saving sqlite blob %q/%q: %w", bucket, key, err)
	}
	return nil
}

func loadBlob(d *DB, bucket, key string, dest any) error {
	var data []byte
	err := d.sql.QueryRow(`SELECT value FROM kv WHERE bucket = ? AND key = ?`, bucket, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("loading sqlite blob %q/%q: %w", bucket, key, err)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("unmarshal failed: %w", err)
	}
	return nil
}

// MigrateLegacyPersistence checks the common Phase 0/legacy filenames and
// imports the first existing bbolt snapshot into the configured SQLite file.
func MigrateLegacyPersistence(sqlitePath string) error {
	candidates := []string{sqlitePath + ".bbolt"}
	if strings.HasSuffix(sqlitePath, ".sqlite") {
		candidates = append(candidates, strings.TrimSuffix(sqlitePath, ".sqlite")+".db")
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("checking legacy persistence %q: %w", candidate, err)
		}
		return MigrateLegacyBBolt(sqlitePath, candidate)
	}
	return nil
}

// MigrateLegacyBBolt imports the old bbolt snapshot into a new SQLite DB.
// It is intentionally one-way and idempotent: if the SQLite database already
// contains data, the migration is skipped. The old bbolt file is never
// deleted automatically.
func MigrateLegacyBBolt(sqlitePath, legacyBoltPath string) error {
	if strings.TrimSpace(legacyBoltPath) == "" || strings.TrimSpace(sqlitePath) == "" || legacyBoltPath == sqlitePath {
		return nil
	}
	if _, err := os.Stat(legacyBoltPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("checking legacy bbolt db: %w", err)
	}

	db, err := Open(sqlitePath)
	if err != nil {
		return err
	}
	defer db.Close()

	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM kv`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	boltDB, err := bolt.Open(legacyBoltPath, 0600, &bolt.Options{Timeout: 2 * time.Second, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("opening legacy bbolt db: %w", err)
	}
	defer boltDB.Close()

	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = boltDB.View(func(btx *bolt.Tx) error {
		return btx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if b == nil {
				return nil
			}
			return b.ForEach(func(k, v []byte) error {
				if v == nil {
					return nil
				}
				_, err := tx.Exec(`INSERT INTO kv(bucket, key, value) VALUES(?, ?, ?)`, string(name), string(k), append([]byte(nil), v...))
				return err
			})
		})
	})
	if err != nil {
		return fmt.Errorf("migrating legacy bbolt data: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing legacy migration: %w", err)
	}
	return nil
}

func (d *DB) ClearAll() error { _, err := d.sql.Exec(`DELETE FROM kv`); return err }
func (d *DB) Backup(destination string) error {
	if strings.TrimSpace(destination) == "" {
		return errors.New("backup destination is empty")
	}
	if err := os.MkdirAll(dirName(destination), 0750); err != nil {
		return err
	}
	_, _ = d.sql.Exec(`PRAGMA wal_checkpoint(FULL)`)
	escaped := strings.ReplaceAll(destination, "'", "''")
	_, err := d.sql.Exec(`VACUUM INTO '` + escaped + `'`)
	return err
}
