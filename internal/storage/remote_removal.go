package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const remoteRemovalMode = "remote"

// PrepareRemoteRemoval binds a signed order already verified by the caller to
// one local operation and challenge. Repeating the poll returns the same pair.
func (s *Store) PrepareRemoteRemoval(ctx context.Context, order managed.RemoteRemovalOrder) (RemovalOperation, error) {
	if err := order.Validate(); err != nil {
		return RemovalOperation{}, err
	}
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
	now := time.Now().UTC()
	if order.AgentID != state.AgentID || order.EnrollmentID != state.EnrollmentID || !now.Before(order.ExpiresAt) {
		return RemovalOperation{}, errors.New("remote removal order does not match the active enrollment or has expired")
	}
	var id string
	err = tx.QueryRowContext(ctx, "SELECT operation_id FROM remote_removal_operations WHERE order_id=?", order.ID).Scan(&id)
	if err == nil {
		op, err := child.Removal(ctx, id)
		if err != nil {
			return op, err
		}
		return op, child.checkRemoteRemoval(ctx, state, op, order.ID, now)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return RemovalOperation{}, err
	}
	if err := child.ordinaryRemovalAllowed(ctx); err != nil {
		return RemovalOperation{}, err
	}
	op, err := child.prepareRemoval(ctx, remoteRemovalMode, now)
	if err != nil {
		return op, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO remote_removal_operations(operation_id,order_id,agent_id,enrollment_id,expires_at_ns) VALUES(?,?,?,?,?)`,
		op.ID, order.ID, order.AgentID, order.EnrollmentID, order.ExpiresAt.UnixNano()); err != nil {
		return op, err
	}
	return op, tx.Commit()
}

func (s *Store) AuthorizeRemoteRemoval(ctx context.Context, operationID string, order managed.RemoteRemovalOrder, grant managed.SignedRemovalGrant) (RemovalOperation, error) {
	return s.authorizeRemoval(ctx, operationID, &grant, "", &order)
}

// BeginRemoteRemoval journals removal start for precisely the order approved
// by the daemon and requires its authorization audit to be acknowledged.
func (s *Store) BeginRemoteRemoval(ctx context.Context, operationID, orderID string) (RemovalOperation, error) {
	if orderID == "" {
		return RemovalOperation{}, errors.New("a remote removal order is required")
	}
	return s.remoteRemovalExecution(ctx, operationID, orderID)
}

// CheckRemoteRemoval verifies the package scriptlet's exact operation. Both
// the authorization and removal-start audits must have reached Central.
func (s *Store) CheckRemoteRemoval(ctx context.Context, operationID string) error {
	_, err := s.remoteRemovalExecution(ctx, operationID, "")
	return err
}

func (s *Store) remoteRemovalExecution(ctx context.Context, operationID, orderID string) (RemovalOperation, error) {
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
	op, err := child.Removal(ctx, operationID)
	if err != nil {
		return op, err
	}
	now := time.Now().UTC()
	if err := child.checkRemoteRemoval(ctx, state, op, orderID, now); err != nil {
		return op, err
	}
	if op.State != "authorized" && op.State != "executing" || op.AuditSequence == 0 {
		return op, errors.New("remote removal has no current authorization")
	}
	if orderID == "" {
		if op.State != "executing" {
			return op, errors.New("remote removal has not started")
		}
		var ack uint64
		if err := tx.QueryRowContext(ctx, "SELECT acknowledged FROM delivery_checkpoint WHERE singleton=1").Scan(&ack); err != nil {
			return op, err
		}
		if ack < op.AuditSequence {
			return op, errors.New("central removal start audit has not been acknowledged")
		}
		return op, nil
	}
	op, err = child.startRemoval(ctx, op, now)
	if err != nil {
		return op, err
	}
	return op, tx.Commit()
}

func (s *Store) checkRemoteRemoval(ctx context.Context, state ManagedState, op RemovalOperation, expectedOrderID string, now time.Time) error {
	if op.Mode != remoteRemovalMode {
		return errors.New("removal operation has no remote authorization")
	}
	var orderID, agentID, enrollmentID string
	var expiry int64
	err := s.executor().QueryRowContext(ctx, `SELECT order_id,agent_id,enrollment_id,expires_at_ns FROM remote_removal_operations WHERE operation_id=?`, op.ID).Scan(&orderID, &agentID, &enrollmentID, &expiry)
	if err != nil {
		return err
	}
	if expectedOrderID != "" && orderID != expectedOrderID || op.AuthorizationID != "" && orderID != op.AuthorizationID || agentID != state.AgentID || enrollmentID != state.EnrollmentID || expiry <= now.UnixNano() {
		return errors.New("remote removal operation is expired or does not match the active order and enrollment")
	}
	return s.ordinaryRemovalAllowed(ctx)
}
