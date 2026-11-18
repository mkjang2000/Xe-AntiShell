package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (s *Store) DeliveryStatus(ctx context.Context) (DeliveryStatus, error) {
	var result DeliveryStatus
	var disconnected, recovered, drained int64
	err := s.db.QueryRowContext(ctx, `
SELECT spool_id, acknowledged, lost_records, pending_records, pending_bytes,
       disconnect_at_ns, first_recovery_ack_ns, drained_at_ns,
       CASE WHEN disconnect_at_ns=0 THEN 0 WHEN drained_at_ns=0 THEN lost_records-losses_at_disconnect
            ELSE losses_at_drain-losses_at_disconnect END
FROM delivery_checkpoint JOIN outbox_usage USING(singleton) WHERE singleton=1`).
		Scan(&result.SpoolID, &result.Acknowledged, &result.LostRecords, &result.Pending, &result.PendingBytes,
			&disconnected, &recovered, &drained, &result.OutageLostRecords)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	result.DisconnectAt = optionalTime(disconnected)
	result.FirstRecoveryACKAt = optionalTime(recovered)
	result.DrainedAt = optionalTime(drained)
	return result, err
}

func optionalTime(ns int64) *time.Time {
	if ns == 0 {
		return nil
	}
	at := time.Unix(0, ns).UTC()
	return &at
}

// RecordDeliveryFailure starts an observed backlog interval on a failed send.
// A partial recovery remains the same interval until the backlog drains.
func (s *Store) RecordDeliveryFailure(ctx context.Context, spoolID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE delivery_checkpoint SET disconnect_at_ns=?, first_recovery_ack_ns=0, drained_at_ns=0,
                              losses_at_disconnect=lost_records, losses_at_drain=0
WHERE singleton=1 AND spool_id=? AND (disconnect_at_ns=0 OR drained_at_ns>0)
  AND EXISTS (SELECT 1 FROM delivery_outbox LIMIT 1)`, at.UTC().UnixNano(), spoolID)
	return err
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM delivery_outbox WHERE sequence<=?", ack.Acknowledged); err != nil {
		return err
	}
	// Expressions use the previous checkpoint and the remaining transactional
	// queue. No-op, stale and rejected ACKs cannot claim delivery recovery.
	now := time.Now().UTC().UnixNano()
	result, err := tx.ExecContext(ctx, `
UPDATE delivery_checkpoint SET
  first_recovery_ack_ns=CASE WHEN disconnect_at_ns>0 AND first_recovery_ack_ns=0 AND acknowledged<?1
                             THEN max(?2,disconnect_at_ns) ELSE first_recovery_ack_ns END,
  drained_at_ns=CASE WHEN disconnect_at_ns>0 AND drained_at_ns=0 AND acknowledged<?1 AND u.pending_records=0
                     THEN max(?2,disconnect_at_ns,first_recovery_ack_ns) ELSE drained_at_ns END,
  losses_at_drain=CASE WHEN disconnect_at_ns>0 AND drained_at_ns=0 AND acknowledged<?1 AND u.pending_records=0
                       THEN lost_records ELSE losses_at_drain END,
  acknowledged=?1
FROM outbox_usage u
WHERE delivery_checkpoint.singleton=u.singleton AND delivery_checkpoint.singleton=1 AND spool_id=?3 AND acknowledged<=?1`,
		ack.Acknowledged, now, ack.SpoolID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("stale delivery acknowledgement")
	}
	return tx.Commit()
}
