package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const MaxSpoolBytes = 256 << 20

type ManagedState struct {
	URL             string                   `json:"url"`
	AgentID         string                   `json:"agent_id"`
	EnrollmentID    string                   `json:"enrollment_id"`
	CAPEM           string                   `json:"ca_pem"`
	CertificatePEM  string                   `json:"certificate_pem"`
	KeyPEM          string                   `json:"key_pem"`
	PolicyKeyID     string                   `json:"policy_key_id"`
	PolicyPublicKey string                   `json:"policy_public_key"`
	Recovery        managed.RecoveryVerifier `json:"recovery"`
}
type DeliveryStatus struct {
	SpoolID      string `json:"spool_id"`
	Acknowledged uint64 `json:"acknowledged"`
	Pending      int    `json:"pending"`
	PendingBytes int64  `json:"pending_bytes"`
	LostRecords  uint64 `json:"lost_records"`
}

func (s *Store) ManagedState(ctx context.Context) (ManagedState, error) {
	var raw []byte
	err := s.executor().QueryRowContext(ctx, "SELECT state_json FROM managed_state WHERE singleton=1").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedState{}, ErrNotFound
	}
	if err != nil {
		return ManagedState{}, err
	}
	var state ManagedState
	err = json.Unmarshal(raw, &state)
	return state, err
}
func (s *Store) SaveManagedState(ctx context.Context, state ManagedState) error {
	if state.AgentID == "" || state.EnrollmentID == "" || state.KeyPEM == "" {
		return errors.New("incomplete enrollment")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO managed_state(singleton,state_json) VALUES(1,?)", raw); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO delivery_checkpoint(singleton,spool_id) VALUES(1,?)", identity.NewID("spool")); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM pending_enrollment WHERE singleton=1"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) enqueue(ctx context.Context, kind, id string, payload []byte) error {
	if err := (managed.Record{Sequence: 1, Kind: kind, ID: id, Payload: payload}).Validate(); err != nil {
		return err
	}
	if len(payload) > 512<<10 {
		_, err := s.executor().ExecContext(ctx, "UPDATE delivery_checkpoint SET lost_records=lost_records+1 WHERE singleton=1")
		return err
	}
	var existing []byte
	err := s.executor().QueryRowContext(ctx, "SELECT payload FROM delivery_outbox WHERE kind=? AND record_id=?", kind, id).Scan(&existing)
	if err == nil {
		if !bytes.Equal(existing, payload) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var size int64
	if err := s.executor().QueryRowContext(ctx, "SELECT COALESCE(sum(length(payload)),0) FROM delivery_outbox").Scan(&size); err != nil {
		return err
	}
	if size+int64(len(payload)) > MaxSpoolBytes {
		_, err := s.executor().ExecContext(ctx, "UPDATE delivery_checkpoint SET lost_records=lost_records+1 WHERE singleton=1")
		return err
	}
	_, err = s.executor().ExecContext(ctx, "INSERT INTO delivery_outbox(kind,record_id,payload,created_at_ns) VALUES(?,?,?,?)", kind, id, payload, time.Now().UTC().UnixNano())
	return err
}
func (s *Store) EnqueueAudit(ctx context.Context, audit managed.AuditRecord) error {
	raw, err := json.Marshal(audit)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	child := &Store{db: s.db, tx: tx}
	if err := child.enqueue(ctx, managed.RecordKindAudit, audit.ID, raw); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DeliveryStatus(ctx context.Context) (DeliveryStatus, error) {
	var result DeliveryStatus
	err := s.db.QueryRowContext(ctx, "SELECT spool_id,acknowledged,lost_records FROM delivery_checkpoint WHERE singleton=1").Scan(&result.SpoolID, &result.Acknowledged, &result.LostRecords)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(length(payload)),0) FROM delivery_outbox").Scan(&result.Pending, &result.PendingBytes)
	return result, err
}
func (s *Store) DeliveryBatch(ctx context.Context, limit int) (managed.Batch, error) {
	if limit < 1 || limit > 64 {
		limit = 32
	}
	state, err := s.ManagedState(ctx)
	if err != nil {
		return managed.Batch{}, err
	}
	status, err := s.DeliveryStatus(ctx)
	if err != nil {
		return managed.Batch{}, err
	}
	batch := managed.Batch{EnrollmentID: state.EnrollmentID, SpoolID: status.SpoolID, Records: []managed.Record{}}
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,kind,record_id,payload FROM delivery_outbox ORDER BY sequence LIMIT ?", limit)
	if err != nil {
		return batch, err
	}
	defer rows.Close()
	size := 0
	for rows.Next() {
		var item managed.Record
		if err := rows.Scan(&item.Sequence, &item.Kind, &item.ID, &item.Payload); err != nil {
			return batch, err
		}
		if size+len(item.Payload) > 2<<20 && len(batch.Records) > 0 {
			break
		}
		batch.Records = append(batch.Records, item)
		size += len(item.Payload)
	}
	return batch, rows.Err()
}
func (s *Store) Acknowledge(ctx context.Context, ack managed.Ack, sent managed.Batch) error {
	if ack.SpoolID != sent.SpoolID || len(sent.Records) == 0 || ack.Acknowledged > sent.Records[len(sent.Records)-1].Sequence || ack.Acknowledged < sent.Records[0].Sequence-1 {
		return errors.New("invalid delivery acknowledgement")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE delivery_checkpoint SET acknowledged=? WHERE singleton=1 AND spool_id=? AND acknowledged<=?", ack.Acknowledged, ack.SpoolID, ack.Acknowledged)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("stale delivery acknowledgement")
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM delivery_outbox WHERE sequence<=?", ack.Acknowledged); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SavePolicy(ctx context.Context, policy managed.SignedPolicy) error {
	raw, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision uint64
	var previous []byte
	err = tx.QueryRowContext(ctx, "SELECT revision,signed_json FROM managed_policy WHERE singleton=1").Scan(&revision, &previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if policy.Policy.Revision < revision {
			return errors.New("policy rollback rejected")
		}
		if policy.Policy.Revision == revision {
			if !bytes.Equal(previous, raw) {
				return errors.New("conflicting policy revision")
			}
			return nil
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO managed_policy(singleton,revision,signed_json,applied_at_ns) VALUES(1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,signed_json=excluded.signed_json,applied_at_ns=excluded.applied_at_ns", policy.Policy.Revision, raw, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Policy(ctx context.Context) (managed.SignedPolicy, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT signed_json FROM managed_policy WHERE singleton=1").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return managed.SignedPolicy{}, ErrNotFound
	}
	if err != nil {
		return managed.SignedPolicy{}, err
	}
	var policy managed.SignedPolicy
	err = json.Unmarshal(raw, &policy)
	return policy, err
}
func (s *Store) BackfillDelivery(ctx context.Context, limit int) error {
	// A bounded explicit catch-up is useful after enrollment; new observation
	// delivery is atomic regardless of whether this historical catch-up runs.
	items, err := s.ListFindings(ctx, FindingFilter{Limit: limit})
	if err != nil {
		return err
	}
	byEvent := map[string][]model.Finding{}
	for _, finding := range items {
		for _, id := range finding.EvidenceEventIDs {
			byEvent[id] = append(byEvent[id], finding)
		}
	}
	ids := make([]string, 0, len(byEvent))
	for id := range byEvent {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		event, err := s.GetEvent(ctx, id)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(managed.EventBundle{Event: event, Findings: byEvent[id]})
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		child := &Store{db: s.db, tx: tx}
		if err := child.enqueue(ctx, managed.RecordKindEventBundle, id, raw); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
func auditFor(action, operation, result string) managed.AuditRecord {
	return managed.AuditRecord{ID: identity.NewID("audit"), Action: action, OperationID: operation, OccurredAt: time.Now().UTC(), Result: result}
}
func (s DeliveryStatus) String() string {
	return fmt.Sprintf("pending=%d bytes=%d lost=%d", s.Pending, s.PendingBytes, s.LostRecords)
}
