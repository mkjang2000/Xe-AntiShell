package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestEvidenceOnlyFirstDecisionIsAtomicAndDeliveredOnce(t *testing.T) {
	for _, mode := range []string{"standalone", "managed"} {
		for _, compact := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/compact=%v", mode, compact), func(t *testing.T) {
				ctx := context.Background()
				s, _ := openTestStore(t)
				if mode == "managed" {
					if err := s.SaveManagedState(ctx, ManagedState{AgentID: "agent", EnrollmentID: "enrollment", KeyPEM: "test"}); err != nil {
						t.Fatal(err)
					}
				}
				e := sourceEventWithAncestors()
				e.RawJSON = json.RawMessage(`{"raw":"source"}`)
				if err := s.SaveEvent(ctx, e); err != nil {
					t.Fatal(err)
				}
				if err := s.SaveEvent(ctx, e); err != nil {
					t.Fatal(err)
				}
				var pending bool
				if err := s.db.QueryRowContext(ctx, "SELECT evidence_digest IS X'' FROM events WHERE event_id=?", e.ID).Scan(&pending); err != nil || !pending {
					t.Fatalf("unmarked input: %t %v", pending, err)
				}
				f := managedTestFinding(e)
				// A failed finding insert must leave the first evaluation available.
				invalid := f
				invalid.ID = ""
				if _, err := s.PersistObservationWithHistory(ctx, e, []model.Finding{invalid}, compact); err == nil {
					t.Fatal("invalid finding accepted")
				}
				for attempt := 0; attempt < 2; attempt++ {
					verdict := []model.Finding{f}
					if attempt > 0 {
						verdict = nil
					}
					if inserted, err := s.PersistObservationWithHistory(ctx, e, verdict, compact); err != nil || inserted {
						t.Fatalf("evaluation %d: %t, %v", attempt, inserted, err)
					}
				}
				if _, err := s.GetFinding(ctx, f.ID); err != nil {
					t.Fatal(err)
				}
				var marker string
				if err := s.db.QueryRowContext(ctx, `SELECT CASE WHEN evidence_digest IS NULL THEN 'full' WHEN length(evidence_digest)=32 THEN 'compact' ELSE 'pending' END FROM events WHERE event_id=?`, e.ID).Scan(&marker); err != nil || marker != "full" && !compact || marker != "compact" && compact {
					t.Fatalf("unexpected decision marker %q, %v", marker, err)
				}
				var bundles int
				if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM delivery_outbox WHERE kind=?", managed.RecordKindEventBundle).Scan(&bundles); err != nil {
					t.Fatal(err)
				}
				if mode == "standalone" {
					if bundles != 0 {
						t.Fatal("standalone evidence enqueued")
					}
					return
				}
				batch, err := s.DeliveryBatch(ctx, 4)
				if err != nil || bundles != 1 || len(batch.Records) != 1 {
					t.Fatalf("bundle count %d, %v %v", bundles, batch, err)
				}
				var wire managed.EventBundle
				if err := json.Unmarshal(batch.Records[0].Payload, &wire); err != nil || len(wire.Findings) != 1 || wire.Findings[0].ID != f.ID || (len(wire.Event.RawJSON) == 0) != compact {
					t.Fatalf("bad first bundle %+v, %v", wire, err)
				}
			})
		}
	}
}
