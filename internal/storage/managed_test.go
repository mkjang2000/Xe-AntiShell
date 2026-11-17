package storage

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"xe-antishell/internal/managed"
	"xe-antishell/internal/model"
)

func enrolledTestStore(t *testing.T) *Store {
	t.Helper()
	store, _ := openTestStore(t)
	if err := store.SaveManagedState(context.Background(), ManagedState{AgentID: "agent-test", EnrollmentID: "enrollment-test", KeyPEM: "test-only"}); err != nil {
		t.Fatal(err)
	}
	return store
}

func managedTestFinding(event model.Event) model.Finding {
	return model.Finding{ID: "finding-" + event.ID, RuleID: "test-rule", RuleVersion: "1", CreatedAt: event.EventTime, Severity: "high", Confidence: .95, State: "open", EvidenceEventIDs: []string{event.ID}, ProcessKey: event.Process.Key, Source: "local"}
}

func TestPersistObservationRollsBackEveryComponentOnInvalidFinding(t *testing.T) {
	store := enrolledTestStore(t)
	ctx := context.Background()
	event := testEvent("atomic-invalid", 10, time.Now().UTC())
	finding := managedTestFinding(event)
	finding.EvidenceEventIDs = []string{"not-durable"}
	if err := store.PersistObservation(ctx, event, []model.Finding{finding}); err == nil {
		t.Fatal("accepted finding without durable evidence")
	}
	if _, err := store.GetEvent(ctx, event.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("event survived rollback: %v", err)
	}
	if _, err := store.GetFinding(ctx, finding.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finding survived rollback: %v", err)
	}
	processes, err := store.ListActiveProcesses(ctx, event.BootID, 10)
	if err != nil || len(processes) != 0 {
		t.Fatalf("process survived rollback: %#v %v", processes, err)
	}
	status, err := store.DeliveryStatus(ctx)
	if err != nil || status.Pending != 0 || status.Acknowledged != 0 {
		t.Fatalf("outbox survived rollback: %#v %v", status, err)
	}
	// The failed transaction must not consume the independent delivery sequence.
	finding.EvidenceEventIDs = []string{event.ID}
	if err := store.PersistObservation(ctx, event, []model.Finding{finding}); err != nil {
		t.Fatal(err)
	}
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil || len(batch.Records) != 1 || batch.Records[0].Sequence != 1 {
		t.Fatalf("rollback left a delivery gap: %#v %v", batch, err)
	}
	var bundle managed.EventBundle
	if err := json.Unmarshal(batch.Records[0].Payload, &bundle); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bundle.Findings, []model.Finding{finding}) || bundle.Event.ID != event.ID {
		t.Fatalf("bundle lost evidence or findings: %#v", bundle)
	}
}

func TestDeliverySequencesIgnoreSourceGapsAndIdempotentInsertions(t *testing.T) {
	store := enrolledTestStore(t)
	ctx := context.Background()
	first := testEvent("source-first", 5, time.Now().UTC())
	second := testEvent("source-second", 90, first.EventTime.Add(time.Second))
	for _, event := range []model.Event{first, first, second} {
		if err := store.PersistObservation(ctx, event, nil); err != nil {
			t.Fatal(err)
		}
	}
	audit := managed.AuditRecord{ID: "same-audit", Action: "test", OccurredAt: time.Now().UTC(), Result: "ok"}
	for index := 0; index < 2; index++ {
		if err := store.EnqueueAudit(ctx, audit); err != nil {
			t.Fatal(err)
		}
	}
	third := testEvent("source-third", 300, first.EventTime.Add(2*time.Second))
	if err := store.PersistObservation(ctx, third, nil); err != nil {
		t.Fatal(err)
	}
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Records) != 4 {
		t.Fatalf("idempotent insert created another record: %#v", batch)
	}
	if err := batch.Validate(); err != nil {
		t.Fatalf("source filtering or duplicate insert made a delivery gap: %v", err)
	}
	for index, record := range batch.Records {
		if record.Sequence != uint64(index+1) {
			t.Fatalf("noncontiguous independent delivery sequence: %#v", batch)
		}
	}
}

func TestInvalidAcknowledgementDoesNotDeletePendingEvidence(t *testing.T) {
	store := enrolledTestStore(t)
	ctx := context.Background()
	for index, id := range []string{"ack-first", "ack-second"} {
		if err := store.PersistObservation(ctx, testEvent(id, uint64(index+1), time.Now().UTC()), nil); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, ack := range []managed.Ack{{SpoolID: "another-spool", Acknowledged: 2}, {SpoolID: batch.SpoolID, Acknowledged: 3}} {
		if err := store.Acknowledge(ctx, ack, batch); err == nil {
			t.Fatal("accepted invalid acknowledgement")
		}
		status, err := store.DeliveryStatus(ctx)
		if err != nil || status.Pending != 2 || status.Acknowledged != 0 {
			t.Fatalf("invalid ACK mutated durable delivery: %#v %v", status, err)
		}
	}
	if err := store.Acknowledge(ctx, managed.Ack{SpoolID: batch.SpoolID, Acknowledged: 2}, batch); err != nil {
		t.Fatal(err)
	}
	if err := store.Acknowledge(ctx, managed.Ack{SpoolID: batch.SpoolID, Acknowledged: 1}, batch); err == nil {
		t.Fatal("accepted checkpoint rollback")
	}
	status, err := store.DeliveryStatus(ctx)
	if err != nil || status.Pending != 0 || status.Acknowledged != 2 {
		t.Fatalf("ACK did not commit expected checkpoint: %#v %v", status, err)
	}
}

func TestPolicyCheckpointRejectsEqualRevisionMutationAndRollback(t *testing.T) {
	store := enrolledTestStore(t)
	ctx := context.Background()
	policy := managed.SignedPolicy{Policy: managed.DefaultPolicy("agent-test", "enrollment-test", 4, time.Now().UTC()), KeyID: "key", Signature: "test-signature"}
	if err := store.SavePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePolicy(ctx, policy); err != nil {
		t.Fatal("identical policy was not idempotent:", err)
	}
	conflict := policy
	conflict.Policy.Detection.Enabled = false
	if err := store.SavePolicy(ctx, conflict); err == nil {
		t.Fatal("accepted altered equal revision")
	}
	rollback := policy
	rollback.Policy.Revision = 3
	if err := store.SavePolicy(ctx, rollback); err == nil {
		t.Fatal("accepted policy rollback")
	}
	stored, err := store.Policy(ctx)
	if err != nil || !reflect.DeepEqual(stored, policy) {
		t.Fatalf("rejected policy changed approved state: %#v %v", stored, err)
	}
}
