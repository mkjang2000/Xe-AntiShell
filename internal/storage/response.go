package storage

import (
	"context"
	"encoding/json"
	"time"
	"xe-antishell/internal/managed"
	"xe-antishell/internal/model"
)

// ClaimResponse atomically claims one response and journals its intent before
// a caller may signal a process. A crash after claiming never repeats a kill.
func (s *Store) ClaimResponse(ctx context.Context, findingID, eventID string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO response_claims(finding_id,event_id,created_at_ns) VALUES(?,?,?) ON CONFLICT(finding_id) DO NOTHING", findingID, eventID, time.Now().UTC().UnixNano())
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return false, err
	}
	child := &Store{db: s.db, tx: tx}
	audit := auditFor("response_intent", findingID, "claimed")
	audit.Details = map[string]string{"event_id": eventID}
	raw, _ := json.Marshal(audit)
	if err := child.enqueueRequiredAudit(ctx, audit.ID, raw); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// RecordResponse commits the final finding and response audit together. The
// original event bundle remains immutable; this is a distinct result record.
func (s *Store) RecordResponse(ctx context.Context, finding model.Finding, audit managed.AuditRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	child := &Store{db: s.db, tx: tx}
	if err := child.SaveFinding(ctx, finding); err != nil {
		return err
	}
	body, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	if err := child.enqueue(ctx, managed.RecordKindFinding, finding.ID, body); err != nil {
		return err
	}
	body, err = json.Marshal(audit)
	if err != nil {
		return err
	}
	if err := child.enqueueRequiredAudit(ctx, audit.ID, body); err != nil {
		return err
	}
	return tx.Commit()
}
