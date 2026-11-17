package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// PendingEnrollment keeps the same key and CSR across a lost enrollment
// response. Enrollment tokens are supplied again by the caller, never stored.
type PendingEnrollment struct {
	URL     string `json:"url"`
	AgentID string `json:"agent_id"`
	CAPEM   string `json:"ca_pem"`
	KeyPEM  string `json:"key_pem"`
	CSRPEM  string `json:"csr_pem"`
}

func (s *Store) PendingEnrollment(ctx context.Context) (PendingEnrollment, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT state_json FROM pending_enrollment WHERE singleton=1").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingEnrollment{}, ErrNotFound
	}
	if err != nil {
		return PendingEnrollment{}, err
	}
	var pending PendingEnrollment
	err = json.Unmarshal(raw, &pending)
	return pending, err
}
func (s *Store) SavePendingEnrollment(ctx context.Context, pending PendingEnrollment) error {
	if pending.URL == "" || pending.AgentID == "" || pending.CAPEM == "" || pending.KeyPEM == "" || pending.CSRPEM == "" {
		return errors.New("incomplete pending enrollment")
	}
	raw, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO pending_enrollment(singleton,state_json) VALUES(1,?)", raw)
	return err
}
