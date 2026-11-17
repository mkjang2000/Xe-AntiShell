package storage

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/managed"
)

type RemovalOperation struct {
	ID              string     `json:"operation_id"`
	Challenge       string     `json:"challenge"`
	Mode            string     `json:"mode"`
	AuthorizationID string     `json:"authorization_id,omitempty"`
	State           string     `json:"state"`
	AuditSequence   uint64     `json:"audit_sequence"`
	CreatedAt       time.Time  `json:"created_at"`
	AuthorizedAt    *time.Time `json:"authorized_at,omitempty"`
}

func (s *Store) CreateRemoval(ctx context.Context) (RemovalOperation, error) {
	challenge, err := managed.NewChallenge()
	if err != nil {
		return RemovalOperation{}, err
	}
	op := RemovalOperation{ID: identity.NewID("removal"), Challenge: challenge, State: "prepared", CreatedAt: time.Now().UTC()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op, err
	}
	defer tx.Rollback()
	child := &Store{db: s.db, tx: tx}
	if _, err := child.ManagedState(ctx); err != nil {
		return op, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO removal_operations(operation_id,challenge,state,created_at_ns) VALUES(?,?,?,?)", op.ID, op.Challenge, op.State, op.CreatedAt.UnixNano())
	if err != nil {
		return op, err
	}
	audit := auditFor("removal_requested", op.ID, "prepared")
	raw, _ := json.Marshal(audit)
	if err := child.enqueue(ctx, managed.RecordKindAudit, audit.ID, raw); err != nil {
		return op, err
	}
	return op, tx.Commit()
}
func (s *Store) Removal(ctx context.Context, id string) (RemovalOperation, error) {
	var op RemovalOperation
	var created, authorized int64
	err := s.executor().QueryRowContext(ctx, "SELECT operation_id,challenge,mode,authorization_id,state,audit_sequence,created_at_ns,authorized_at_ns FROM removal_operations WHERE operation_id=?", id).Scan(&op.ID, &op.Challenge, &op.Mode, &op.AuthorizationID, &op.State, &op.AuditSequence, &created, &authorized)
	if errors.Is(err, sql.ErrNoRows) {
		return op, ErrNotFound
	}
	if err != nil {
		return op, err
	}
	op.CreatedAt = time.Unix(0, created).UTC()
	if authorized > 0 {
		at := time.Unix(0, authorized).UTC()
		op.AuthorizedAt = &at
	}
	return op, nil
}

// AuthorizeRemoval consumes authorization and journals its delivery obligation
// in one transaction. Repeating the same operation is safe after a lost reply.
func (s *Store) AuthorizeRemoval(ctx context.Context, id string, signed *managed.SignedRemovalGrant, recovery string) (RemovalOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RemovalOperation{}, err
	}
	defer tx.Rollback()
	child := &Store{db: s.db, tx: tx}
	state, err := child.ManagedState(ctx)
	if err != nil {
		return RemovalOperation{}, err
	}
	op, err := child.Removal(ctx, id)
	if err != nil {
		return op, err
	}
	now := time.Now().UTC()
	if now.Sub(op.CreatedAt) > managed.MaxRemovalGrantLifetime {
		return op, errors.New("removal operation expired")
	}
	authID, mode := "", ""
	if signed != nil && recovery == "" {
		key, err := managed.DecodePublicKey(state.PolicyPublicKey)
		if err != nil {
			return op, err
		}
		grant, err := managed.VerifyRemovalGrant(*signed, map[string]ed25519.PublicKey{state.PolicyKeyID: key}, state.AgentID, state.EnrollmentID, op.Challenge, now)
		if err != nil {
			return op, err
		}
		var raw []byte
		err = tx.QueryRowContext(ctx, "SELECT signed_json FROM managed_policy WHERE singleton=1").Scan(&raw)
		if err == nil {
			var policy managed.SignedPolicy
			if json.Unmarshal(raw, &policy) != nil {
				return op, errors.New("invalid stored policy")
			}
			if policy.Policy.UninstallMode == "deny" {
				return op, errors.New("policy denies ordinary removal")
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return op, err
		}
		authID, mode = grant.ID, "central"
	} else if signed == nil && recovery != "" {
		if !managed.VerifyRecoveryCode(state.Recovery, state.AgentID, state.EnrollmentID, recovery) {
			return op, errors.New("invalid recovery authorization")
		}
		authID, mode = "recovery:"+state.Recovery.ID, "recovery"
	} else {
		return op, errors.New("exactly one removal authorization is required")
	}
	if op.State == "authorized" && op.AuthorizationID == authID {
		return op, nil
	}
	if op.State != "prepared" {
		return op, errors.New("removal operation already consumed")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO consumed_authorizations(authorization_id,operation_id,consumed_at_ns) VALUES(?,?,?)", authID, id, now.UnixNano()); err != nil {
		return op, errors.New("authorization has already been consumed")
	}
	audit := auditFor("removal_authorized", id, mode)
	raw, _ := json.Marshal(audit)
	if err := child.enqueueRequiredAudit(ctx, audit.ID, raw); err != nil {
		return op, err
	}
	var sequence uint64
	if err := tx.QueryRowContext(ctx, "SELECT sequence FROM delivery_outbox WHERE kind=? AND record_id=?", managed.RecordKindAudit, audit.ID).Scan(&sequence); err != nil {
		return op, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE removal_operations SET state='authorized',mode=?,authorization_id=?,audit_sequence=?,authorized_at_ns=? WHERE operation_id=?", mode, authID, sequence, now.UnixNano(), id)
	if err != nil {
		return op, err
	}
	op.State, op.Mode, op.AuthorizationID, op.AuditSequence, op.AuthorizedAt = "authorized", mode, authID, sequence, &now
	return op, tx.Commit()
}

func (s *Store) enqueueRequiredAudit(ctx context.Context, id string, raw []byte) error {
	if err := s.enqueue(ctx, managed.RecordKindAudit, id, raw); err != nil {
		return err
	}
	var n int
	if err := s.executor().QueryRowContext(ctx, "SELECT count(*) FROM delivery_outbox WHERE kind=? AND record_id=?", managed.RecordKindAudit, id).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return errors.New("delivery spool is full; cannot authorize removal")
	}
	return nil
}

// BeginRemoval permits only a recent authorization. Normal removal requires
// the central server to have acknowledged the authorization audit first.
func (s *Store) BeginRemoval(ctx context.Context) (RemovalOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RemovalOperation{}, err
	}
	defer tx.Rollback()
	child := &Store{db: s.db, tx: tx}
	var id string
	err = tx.QueryRowContext(ctx, "SELECT operation_id FROM removal_operations WHERE state IN ('authorized','executing') ORDER BY authorized_at_ns DESC LIMIT 1").Scan(&id)
	if err != nil {
		return RemovalOperation{}, errors.New("a current one-use removal authorization is required")
	}
	op, err := child.Removal(ctx, id)
	if err != nil {
		return op, err
	}
	if op.AuthorizedAt == nil || time.Since(*op.AuthorizedAt) > managed.MaxRemovalGrantLifetime {
		return op, errors.New("removal authorization expired")
	}
	if op.State == "executing" {
		return op, nil
	}
	if op.Mode != "recovery" {
		var ack uint64
		if err := tx.QueryRowContext(ctx, "SELECT acknowledged FROM delivery_checkpoint WHERE singleton=1").Scan(&ack); err != nil {
			return op, err
		}
		if ack < op.AuditSequence {
			return op, errors.New("central removal audit has not been acknowledged")
		}
	}
	audit := auditFor("removal_started", id, op.Mode)
	raw, _ := json.Marshal(audit)
	if err := child.enqueueRequiredAudit(ctx, audit.ID, raw); err != nil {
		return op, err
	}
	var sequence uint64
	if err := tx.QueryRowContext(ctx, "SELECT sequence FROM delivery_outbox WHERE record_id=? AND kind=?", audit.ID, managed.RecordKindAudit).Scan(&sequence); err != nil {
		return op, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE removal_operations SET state='executing',audit_sequence=? WHERE operation_id=?", sequence, id)
	if err != nil {
		return op, err
	}
	op.State, op.AuditSequence = "executing", sequence
	return op, tx.Commit()
}
