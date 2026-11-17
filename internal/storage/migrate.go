package storage

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version  int
	name     string
	checksum string
	sql      string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("storage: read embedded migrations: %w", err)
	}

	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("storage: migration %q has no numeric prefix", entry.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil || version < 1 {
			return nil, fmt.Errorf("storage: migration %q has invalid version", entry.Name())
		}
		body, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("storage: read migration %q: %w", entry.Name(), err)
		}
		digest := sha256.Sum256(body)
		migrations = append(migrations, migration{
			version:  version,
			name:     entry.Name(),
			checksum: hex.EncodeToString(digest[:]),
			sql:      string(body),
		})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	for index, item := range migrations {
		expected := index + 1
		if item.version != expected {
			return nil, fmt.Errorf("storage: migration sequence has version %d, expected %d", item.version, expected)
		}
	}
	return migrations, nil
}

func (s *Store) migrate(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return fmt.Errorf("storage: no embedded migrations")
	}

	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version       INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    checksum      TEXT NOT NULL,
    applied_at_ns INTEGER NOT NULL
)`); err != nil {
		return fmt.Errorf("storage: create migration ledger: %w", err)
	}

	applied := make(map[int]string)
	rows, err := s.db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("storage: read migration ledger: %w", err)
	}
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			_ = rows.Close()
			return fmt.Errorf("storage: scan migration ledger: %w", err)
		}
		applied[version] = checksum
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("storage: close migration rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("storage: iterate migration ledger: %w", err)
	}

	latestKnown := migrations[len(migrations)-1].version
	for version := range applied {
		if version > latestKnown {
			return fmt.Errorf("storage: database schema version %d is newer than supported version %d", version, latestKnown)
		}
	}

	for _, item := range migrations {
		if checksum, ok := applied[item.version]; ok {
			if checksum != item.checksum {
				return fmt.Errorf("storage: applied migration %d checksum mismatch", item.version)
			}
			continue
		}
		if err := s.applyMigration(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, item migration) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("storage: acquire migration connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("storage: begin migration %d: %w", item.version, err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	if _, err := conn.ExecContext(ctx, item.sql); err != nil {
		return fmt.Errorf("storage: apply migration %d: %w", item.version, err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, name, checksum, applied_at_ns) VALUES (?, ?, ?, ?)`,
		item.version, item.name, item.checksum, time.Now().UTC().UnixNano(),
	); err != nil {
		return fmt.Errorf("storage: record migration %d: %w", item.version, err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("storage: commit migration %d: %w", item.version, err)
	}
	committed = true
	return nil
}
