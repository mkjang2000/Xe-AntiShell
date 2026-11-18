package storage

import (
	"context"
	"database/sql"
)

// OpenEphemeral gives offline replay the normal schema on a private in-memory
// connection. Closing it discards all input and derived evidence.
func OpenEphemeral(ctx context.Context) (*Store, error) {
	db, err := sql.Open("sqlite", "file::memory:?mode=memory&cache=private&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}
