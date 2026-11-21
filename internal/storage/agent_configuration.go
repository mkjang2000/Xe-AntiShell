package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const agentConfigurationMetadata = "managed_agent_configuration_v1"

type AgentConfigurationCheckpoint struct {
	Signed          managed.SignedAgentConfiguration `json:"signed"`
	AppliedAt       time.Time                        `json:"applied_at"`
	PanelGeneration string                           `json:"panel_generation"`
}

func (s *Store) AgentConfiguration(ctx context.Context) (AgentConfigurationCheckpoint, error) {
	var checkpoint AgentConfigurationCheckpoint
	var raw []byte
	err := s.executor().QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", agentConfigurationMetadata).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return checkpoint, ErrNotFound
	}
	if err == nil {
		err = managed.DecodeStrict(raw, managed.MaxAgentConfigurationBytes+1024, &checkpoint)
	}
	return checkpoint, err
}

func (s *Store) SaveAgentConfiguration(ctx context.Context, checkpoint AgentConfigurationCheckpoint, base uint64) error {
	body, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	child := &Store{db: s.db, tx: tx}
	enrolled, err := child.ManagedState(ctx)
	config := checkpoint.Signed.Configuration
	if err != nil || enrolled.AgentID != config.AgentID || enrolled.EnrollmentID != config.EnrollmentID {
		return ErrConflict
	}
	current, err := child.AgentConfiguration(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	var revision uint64
	if current.Signed.Configuration.EnrollmentID == config.EnrollmentID {
		revision = current.Signed.Configuration.Revision
	}
	if revision != base || config.Revision <= revision {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO metadata(key,value,updated_at_ns) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at_ns=excluded.updated_at_ns`,
		agentConfigurationMetadata, body, checkpoint.AppliedAt.UnixNano()); err != nil {
		return err
	}
	return tx.Commit()
}
