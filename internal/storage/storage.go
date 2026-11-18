// Package storage provides the daemon-owned durable SQLite store.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound indicates that the requested durable object does not exist.
	ErrNotFound = errors.New("storage: not found")
	// ErrConflict indicates that an immutable identifier was reused for
	// different content.
	ErrConflict = errors.New("storage: conflicting immutable object")
)

// Store owns a SQLite database. The daemon is expected to be the only process
// that opens the database; local clients query it through the daemon API.
type Store struct {
	db   *sql.DB
	tx   *sql.Tx
	path string
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) executor() sqlExecutor {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

// Open opens path, configures durable WAL mode, and applies embedded schema
// migrations. The containing directory must already exist.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("storage: empty database path")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve database path: %w", err)
	}
	if err := prepareDatabaseFile(absPath); err != nil {
		return nil, err
	}

	dsnURL := &url.URL{Scheme: "file", Path: absPath}
	query := dsnURL.Query()
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "busy_timeout(5000)")
	// Reserve the writer before reading in a write transaction. A deferred
	// read-to-write upgrade can otherwise fail immediately under WAL contention.
	query.Set("_txlock", "immediate")
	dsnURL.RawQuery = query.Encode()

	db, err := sql.Open("sqlite", dsnURL.String())
	if err != nil {
		return nil, fmt.Errorf("storage: open sqlite: %w", err)
	}
	// One owned connection queues daemon writes before SQLite rather than
	// letting policy, delivery, retention and evidence writers contend for its
	// lock. Reads queue too; callers retain their context cancellation. Methods
	// must close query rows before issuing a separate query or transaction.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{db: db, path: absPath}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: ping sqlite: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(absPath, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: restrict database permissions: %w", err)
	}

	return store, nil
}

func prepareDatabaseFile(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("storage: database path %q is not a regular file", path)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("storage: restrict existing database permissions: %w", err)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("storage: inspect database path: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("storage: create database file securely: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("storage: close new database file: %w", err)
	}
	return nil
}

// Close flushes and closes the SQLite database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		_ = s.db.Close()
		return fmt.Errorf("storage: checkpoint before close: %w", err)
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("storage: close sqlite: %w", err)
	}
	return nil
}
