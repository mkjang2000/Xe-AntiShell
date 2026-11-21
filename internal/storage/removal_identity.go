package storage

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
)

// ReadManagedStateForRemoval loads the current enrollment without modifying the
// daemon's database. The packaged worker checks the canonical path and owner.
// It needs its own connection because the authorized RPM erase stops the daemon
// before the worker can send the final result.
func ReadManagedStateForRemoval(ctx context.Context, path string) (ManagedState, error) {
	if !filepath.IsAbs(path) {
		return ManagedState{}, errors.New("storage: removal identity requires an absolute database path")
	}
	dsn := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return ManagedState{}, err
	}
	defer db.Close()
	return (&Store{db: db}).ManagedState(ctx)
}
