package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"modernc.org/sqlite"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

const observationBeginAttempts = 2
const observationBeginBackoff = 25 * time.Millisecond

// beginObservation retries only writer reservation, before any event data or
// transaction side effect exists. Never replay the transaction after a body or
// COMMIT error: database/sql may already have released that transaction.
// Each SQLite wait retains the configured five-second busy timeout; at most
// two attempts plus this cancellable backoff are made. Pool acquisition also
// respects the caller's context.
func beginObservation(ctx context.Context, begin func(context.Context, *sql.TxOptions) (*sql.Tx, error)) (*sql.Tx, error) {
	for attempt := 0; ; attempt++ {
		tx, err := begin(ctx, nil)
		if err == nil || attempt+1 >= observationBeginAttempts || !sqliteContention(err) {
			return tx, err
		}
		timer := time.NewTimer(observationBeginBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func sqliteContention(err error) bool {
	var value *sqlite.Error
	if !errors.As(err, &value) {
		return false
	}
	// SQLite extended result codes preserve the primary code in the low byte.
	primary := value.Code() & 0xff
	return primary == 5 || primary == 6 // SQLITE_BUSY / SQLITE_LOCKED
}

// PersistObservation commits evidence, its derived findings and its delivery
// obligation together. A crash cannot strand an accepted managed observation.
func (s *Store) PersistObservation(ctx context.Context, event model.Event, findings []model.Finding) error {
	_, err := s.PersistObservationResult(ctx, event, findings)
	return err
}

// PersistObservationResult reports whether the committed transaction inserted
// a new event. A duplicate or a failed transaction returns false.
func (s *Store) PersistObservationResult(ctx context.Context, event model.Event, findings []model.Finding) (bool, error) {
	return s.PersistObservationWithHistory(ctx, event, findings, false)
}

// PersistObservationWithHistory can retain a minimal event and delivery payload
// after evaluation, while keeping the source digest for immutable ID checks.
func (s *Store) PersistObservationWithHistory(ctx context.Context, event model.Event, findings []model.Finding, compact bool) (bool, error) {
	tx, err := beginObservation(ctx, s.db.BeginTx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	child := &Store{db: s.db, tx: tx}
	inserted, eventJSON, err := child.saveEventResult(ctx, event, compact, true)
	if err != nil {
		return false, err
	}
	for _, process := range append(append([]model.Process(nil), event.Ancestors...), event.Process) {
		if process.Key != "" && process.PID > 0 {
			if compact {
				process = compactProcess(process)
			}
			var err error
			if isContextObservation(event.Type) {
				err = child.saveProcessContext(ctx, event.BootID, process)
			} else {
				err = child.SaveProcess(ctx, event.BootID, process)
			}
			if err != nil {
				return false, err
			}
		}
	}
	// Keep the original verdict and its immutable delivery obligation, including
	// when a rule or its temporary exception has changed since first receipt.
	firstEvaluation := eventJSON != nil
	if !firstEvaluation {
		findings = nil
	}
	for _, finding := range findings {
		if err := child.SaveFinding(ctx, finding); err != nil {
			return false, err
		}
	}
	if firstEvaluation {
		var enabled int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM managed_state").Scan(&enabled); err != nil {
			return false, err
		}
		if enabled > 0 {
			payload, err := marshalEventBundle(eventJSON, findings)
			if err != nil {
				return false, err
			}
			if err := child.enqueue(ctx, managed.RecordKindEventBundle, event.ID, payload); err != nil {
				return false, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return inserted, nil
}

// marshalEventBundle accepts only event JSON freshly encoded by saveEventResult
// in this same observation. Both fields already have encoding/json's escaping;
// assembling the fixed protocol envelope avoids scanning the event a second
// time. Imported or caller-provided bytes must never enter this private path.
// This mirrors the pinned EventBundle's two fields; changes to its fields or
// MarshalJSON require reviewing this helper and the byte-equivalence tests.
func marshalEventBundle(eventJSON json.RawMessage, findings []model.Finding) ([]byte, error) {
	findingJSON, err := json.Marshal(findings)
	if err != nil {
		return nil, err
	}
	const eventPrefix = `{"event":`
	const findingsPrefix = `,"findings":`
	payload := make([]byte, 0, len(eventPrefix)+len(eventJSON)+len(findingsPrefix)+len(findingJSON)+1)
	payload = append(payload, eventPrefix...)
	payload = append(payload, eventJSON...)
	payload = append(payload, findingsPrefix...)
	payload = append(payload, findingJSON...)
	return append(payload, '}'), nil
}
