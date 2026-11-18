package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

func TestCompactObservationRetainsTypedEvidenceAndRejectsConflictingRetry(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	if err := s.SaveManagedState(ctx, ManagedState{AgentID: "agent", EnrollmentID: "enrollment", KeyPEM: "test"}); err != nil {
		t.Fatal(err)
	}
	e := sourceEventWithAncestors()
	e.RawJSON = json.RawMessage(`{"extra":"discarded"}`)
	e.Process.CWD = "/srv/site"
	e.Process.OriginService = "example.service"
	before, _ := json.Marshal(e)
	if inserted, err := s.PersistObservationWithHistory(ctx, e, nil, true); err != nil || !inserted {
		t.Fatalf("persist: %t %v", inserted, err)
	}
	after, _ := json.Marshal(e)
	if string(before) != string(after) {
		t.Fatal("projection changed input needed by response and lineage")
	}
	batch, err := s.DeliveryBatch(ctx, 1)
	if err != nil || len(batch.Records) != 1 {
		t.Fatalf("batch: %+v %v", batch, err)
	}
	var wire managed.EventBundle
	if err := json.Unmarshal(batch.Records[0].Payload, &wire); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetEvent(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []model.Event{stored, wire.Event} {
		if current.ID != e.ID || current.Process.Key != e.Process.Key || current.Process.OriginService != "example.service" ||
			len(current.RawJSON)+len(current.Ancestors)+len(current.Process.Argv) != 0 || current.Process.CWD != "" {
			t.Fatalf("incorrect compact evidence: %+v", current)
		}
	}
	e.IngestTime = e.IngestTime.Add(time.Second)
	if inserted, err := s.PersistObservationWithHistory(ctx, e, nil, true); err != nil || inserted {
		t.Fatalf("stable retry: %t %v", inserted, err)
	}
	e.Ancestors[0].Exe = "different"
	if _, err := s.PersistObservationWithHistory(ctx, e, nil, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("discarded field conflict: %v", err)
	}
	cutoff := e.EventTime.Add(time.Hour)
	if n, err := s.DeleteEventsBefore(ctx, cutoff, 10); err != nil || n != 0 {
		t.Fatalf("expired pending event: %d %v", n, err)
	}
	ack := managed.Ack{SpoolID: batch.SpoolID, Acknowledged: batch.Records[0].Sequence}
	if err := s.Acknowledge(ctx, ack, batch); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteEventsBefore(ctx, cutoff, 10); err != nil || n != 1 {
		t.Fatalf("expired acknowledged event: %d %v", n, err)
	}
}

func TestCompactHistoryPreservesFindingEvidenceAndLegacyRetry(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	e := sourceEventWithAncestors()
	if err := s.SaveEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	finding := managedTestFinding(e)
	finding.RiskScore = 75
	if inserted, err := s.PersistObservationWithHistory(ctx, e, []model.Finding{finding}, true); err != nil || inserted {
		t.Fatalf("legacy retry: %t %v", inserted, err)
	}
	if removed, err := s.DeleteEventsBefore(ctx, e.EventTime.Add(time.Hour), 10); err != nil || removed != 0 {
		t.Fatalf("protected evidence expired: %d %v", removed, err)
	}
	got, err := s.GetFinding(ctx, finding.ID)
	if err != nil || got.RuleID != finding.RuleID || got.RiskScore != 75 || len(got.EvidenceEventIDs) != 1 {
		t.Fatalf("finding lost structured evidence: %+v %v", got, err)
	}
}
