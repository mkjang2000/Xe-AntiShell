package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

// holdExternalWriter uses a second SQLite connection, not the agent pool. This
// models an actual competing writer while the normal one-connection queue is
// free. The returned release is idempotent and also registered for cleanup.
func holdExternalWriter(t *testing.T, path string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		_ = db.Close()
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			_ = conn.Close()
			_ = db.Close()
		})
	}
	t.Cleanup(release)
	return release
}

func shortObservationWait(t *testing.T, store *Store) {
	t.Helper()
	// Only the disposable test DB uses a short native wait, so actual SQLite
	// BUSY and retry outcomes can be exercised without five-second sleeps.
	if _, err := store.db.Exec("PRAGMA busy_timeout=1"); err != nil {
		t.Fatal(err)
	}
}

func TestObservationBeginRetriesRealWriterContentionBeforeMutation(t *testing.T) {
	store, path := openTestStore(t)
	shortObservationWait(t, store)
	release := holdExternalWriter(t, path)
	attempts := 0
	tx, err := beginObservation(context.Background(), func(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
		attempts++
		tx, err := store.db.BeginTx(ctx, opts)
		if attempts == 1 {
			if !sqliteContention(err) {
				t.Fatalf("held writer did not produce typed SQLite contention: %v", err)
			}
			release()
		}
		return tx, err
	})
	if err != nil || attempts != 2 {
		t.Fatalf("retry after actual lock release: attempts=%d err=%v", attempts, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveManagedState(context.Background(), ManagedState{AgentID: "agent-test", EnrollmentID: "enrollment-test", KeyPEM: "fixture"}); err != nil {
		t.Fatal(err)
	}
	event := testEvent("after-writer-recovery", 1, time.Now().UTC())
	for i := 0; i < 2; i++ {
		if err := store.PersistObservation(context.Background(), event, nil); err != nil {
			t.Fatal(err)
		}
	}
	status, err := store.DeliveryStatus(context.Background())
	if err != nil || status.Pending != 1 || status.LostRecords != 0 {
		t.Fatalf("recovery/idempotent retry altered delivery: %#v %v", status, err)
	}
}

func TestObservationLockExhaustionLeavesNoPartialEvidenceAndCanRecover(t *testing.T) {
	store, path := openTestStore(t)
	shortObservationWait(t, store)
	release := holdExternalWriter(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempts := 0
	_, err := beginObservation(ctx, func(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
		attempts++
		return store.db.BeginTx(ctx, opts)
	})
	if !sqliteContention(err) || attempts != observationBeginAttempts {
		t.Fatalf("unbounded or wrongly classified reservation failure: attempts=%d err=%v", attempts, err)
	}
	event := testEvent("exhausted-then-recovered", 1, time.Now().UTC())
	if err := store.PersistObservation(ctx, event, []model.Finding{managedTestFinding(event)}); !sqliteContention(err) {
		t.Fatalf("held writer accepted observation or hid SQLite error: %v", err)
	}
	release()
	if _, err := store.GetEvent(ctx, event.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed reservation left evidence: %v", err)
	}
	if err := store.PersistObservation(ctx, event, []model.Finding{managedTestFinding(event)}); err != nil {
		t.Fatal(err)
	}
}

func TestObservationRetryCancellationAndPermanentErrorsAreNotReplayed(t *testing.T) {
	store, path := openTestStore(t)
	shortObservationWait(t, store)
	release := holdExternalWriter(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	_, err := beginObservation(ctx, func(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
		attempts++
		tx, err := store.db.BeginTx(ctx, opts)
		cancel() // Cancel exactly after the actual failed reservation.
		return tx, err
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("cancellation retried reservation: attempts=%d err=%v", attempts, err)
	}
	release()
	for _, permanent := range []error{ErrConflict, errors.New("database is locked (5) (SQLITE_BUSY)"), sql.ErrConnDone} {
		attempts = 0
		_, err := beginObservation(context.Background(), func(context.Context, *sql.TxOptions) (*sql.Tx, error) {
			attempts++
			return nil, permanent
		})
		if !errors.Is(err, permanent) || attempts != 1 {
			t.Fatalf("permanent/untyped error retried: attempts=%d err=%v", attempts, err)
		}
	}
}

func TestSerializedStorageSupportsConcurrentEvidencePolicyDeliveryAndQueries(t *testing.T) {
	store := enrolledTestStore(t)
	if store.db.Stats().MaxOpenConnections != 1 {
		t.Fatal("agent DB permits competing writer connections")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const events = 45
	var group sync.WaitGroup
	errorsCh := make(chan error, 4)
	policy := managed.SignedPolicy{Policy: managed.DefaultPolicy("agent-test", "enrollment-test", 1, time.Now().UTC()), KeyID: "fixture-key", Signature: "fixture-signature"}
	run := func(work func() error) {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := work(); err != nil {
				errorsCh <- err
			}
		}()
	}
	run(func() error {
		for i := 0; i < events; i++ {
			e := testEvent(fmt.Sprintf("concurrent-%d", i), uint64(i+1), time.Now().UTC())
			if err := store.PersistObservation(ctx, e, []model.Finding{managedTestFinding(e)}); err != nil {
				return err
			}
		}
		return nil
	})
	run(func() error {
		for i := 0; i < 35; i++ {
			if err := store.SavePolicy(ctx, policy); err != nil {
				return err
			}
		}
		return nil
	})
	run(func() error {
		for i := 0; i < 35; i++ {
			batch, err := store.DeliveryBatch(ctx, 16)
			if err != nil {
				return err
			}
			if len(batch.Records) > 0 {
				if err := store.Acknowledge(ctx, managed.Ack{SpoolID: batch.SpoolID, Acknowledged: batch.Records[len(batch.Records)-1].Sequence}, batch); err != nil {
					return err
				}
			}
		}
		return nil
	})
	run(func() error {
		for i := 0; i < 35; i++ {
			if _, err := store.ListFindings(ctx, FindingFilter{Limit: 10}); err != nil {
				return err
			}
			if _, err := store.ListEvents(ctx, EventFilter{Limit: 10}); err != nil {
				return err
			}
			if _, err := store.DeliveryStatus(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	items, err := store.ListEvents(ctx, EventFilter{Limit: events + 1})
	if err != nil || len(items) != events {
		t.Fatalf("concurrent operations lost events: count=%d err=%v", len(items), err)
	}
	status, err := store.DeliveryStatus(ctx)
	if err != nil || status.LostRecords != 0 || uint64(status.Pending)+status.Acknowledged != events {
		t.Fatalf("concurrent operations changed delivery cardinality: %#v %v", status, err)
	}
}

func TestSerializedPoolQueryCancellationDoesNotStarveLaterEvidence(t *testing.T) {
	store, _ := openTestStore(t)
	conn, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = store.ListFindings(ctx, FindingFilter{Limit: 10})
	_ = conn.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("query ignored serialized-pool cancellation: %v", err)
	}
	event := testEvent("after-query-cancellation", 1, time.Now().UTC())
	if err := store.PersistObservation(context.Background(), event, nil); err != nil {
		t.Fatalf("canceled queued query retained connection: %v", err)
	}
}
