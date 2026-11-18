package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

func TestCapacityDayCountsOnlyNewCommittedEventsAndSurvivesRetention(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -35)
	pinned := testEvent("pinned", 1, old)
	f := managedTestFinding(pinned)
	transient := testEvent("transient", 2, old.Add(time.Minute))
	for _, event := range []model.Event{pinned, pinned, transient} {
		if err := s.PersistObservation(ctx, event, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	bad := testEvent("rollback", 3, old)
	f.ID, f.EvidenceEventIDs = "invalid-finding", []string{"missing"}
	if err := s.PersistObservation(ctx, bad, []model.Finding{f}); err == nil {
		t.Fatal("expected rollback")
	}
	a, _ := json.Marshal(pinned)
	b, _ := json.Marshal(transient)
	c, err := s.Capacity(ctx, now, now.AddDate(0, 0, -30))
	if err != nil || c.EventsToday != 2 || c.BytesToday != int64(len(a)+len(b)) || c.YesterdayObserved || c.RetentionBacklog != 1 || c.BacklogTruncated || c.OldestEvent == nil || !c.OldestEvent.Equal(old) {
		t.Fatalf("capacity after replay/rollback: %+v %v", c, err)
	}
	if c.DatabaseBytes == nil || *c.DatabaseBytes == 0 || c.WALBytes == nil || *c.WALBytes == 0 || c.DiskAvailableBytes == nil {
		t.Fatalf("missing disk sample: %+v", c)
	}
	if n, err := s.DeleteEventsBefore(ctx, now, 100); n != 1 || err != nil {
		t.Fatalf("deleted %d: %v", n, err)
	}
	c, err = s.Capacity(ctx, now.AddDate(0, 0, 1), now)
	if err != nil || c.EventsToday != 0 || !c.YesterdayObserved || c.EventsYesterday != 2 || c.BytesYesterday != int64(len(a)+len(b)) || c.RetentionBacklog != 0 {
		t.Fatalf("next UTC day after retention: %+v %v", c, err)
	}
}

func TestCapacityUpgradeAndRecoveryAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v3.db")
	oldDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &Store{db: oldDB}
	if _, err := oldDB.Exec("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT,checksum TEXT,applied_at_ns INTEGER)"); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:3] {
		if err := legacy.applyMigration(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := legacy.SaveManagedState(ctx, ManagedState{AgentID: "old-agent", EnrollmentID: "old-enrollment", KeyPEM: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := oldDB.Exec(`INSERT INTO delivery_outbox(kind,record_id,payload,created_at_ns) VALUES ('audit','one',CAST('{}' AS BLOB),1),('audit','two',CAST('{"n":2}' AS BLOB),2);
UPDATE delivery_checkpoint SET lost_records=7 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err := oldDB.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := s.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	get := func() DeliveryStatus {
		t.Helper()
		d, err := s.DeliveryStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := get(); d.Pending != 2 || d.PendingBytes != 9 || d.LostRecords != 7 || d.DisconnectAt != nil {
		t.Fatalf("upgraded status: %+v", d)
	}
	start := time.Now().UTC().Add(-time.Minute)
	for _, at := range []time.Time{start, start.Add(time.Second)} {
		if err := s.RecordDeliveryFailure(ctx, batch.SpoolID, at); err != nil {
			t.Fatal(err)
		}
	}
	large := managed.AuditRecord{ID: "large", Action: strings.Repeat("x", 513<<10), OccurredAt: start}
	if err := s.EnqueueAudit(ctx, large); err != nil {
		t.Fatal(err)
	}
	ack := func(seq uint64) error {
		return s.Acknowledge(ctx, managed.Ack{SpoolID: batch.SpoolID, Acknowledged: seq}, batch)
	}
	if err := ack(0); err != nil {
		t.Fatal(err)
	}
	if d := get(); !d.DisconnectAt.Equal(start) || d.FirstRecoveryACKAt != nil || d.OutageLostRecords != 1 || d.LostRecords != 8 {
		t.Fatalf("unchanged ACK: %+v", d)
	}
	// Inject an ACK write failure after its DELETE; both usage and rows must roll back.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_ack BEFORE UPDATE OF acknowledged ON delivery_checkpoint BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if err := ack(1); err == nil {
		t.Fatal("injected failure accepted")
	}
	if d := get(); d.PendingBytes != 9 || d.FirstRecoveryACKAt != nil {
		t.Fatalf("rolled-back ACK: %+v", d)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_ack"); err != nil {
		t.Fatal(err)
	}
	if err := ack(1); err != nil {
		t.Fatal(err)
	}
	first := get()
	if first.Pending != 1 || first.PendingBytes != 7 || first.FirstRecoveryACKAt == nil || first.DrainedAt != nil {
		t.Fatalf("partial ACK: %+v", first)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RecordDeliveryFailure(ctx, batch.SpoolID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ack(2); err != nil {
		t.Fatal(err)
	}
	if err := ack(2); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueAudit(ctx, large); err != nil {
		t.Fatal(err)
	}
	d := get()
	if d.Pending != 0 || d.PendingBytes != 0 || !d.FirstRecoveryACKAt.Equal(*first.FirstRecoveryACKAt) || d.DrainedAt == nil || d.DrainedAt.Before(*d.FirstRecoveryACKAt) || !d.DisconnectAt.Equal(start) || d.LostRecords != 9 || d.OutageLostRecords != 1 {
		t.Fatalf("drained: %+v", d)
	}
	if err := s.EnqueueAudit(ctx, managed.AuditRecord{ID: "new", Action: "test", OccurredAt: start}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDeliveryFailure(ctx, batch.SpoolID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if d := get(); d.OutageLostRecords != 0 || d.FirstRecoveryACKAt != nil || d.DrainedAt != nil || !d.DisconnectAt.After(start) {
		t.Fatalf("new outage: %+v", d)
	}
}

func TestOutboxUsageLimitAndLocalEvidence(t *testing.T) {
	ctx := context.Background()
	s := enrolledTestStore(t)
	event := testEvent("overflow", 1, time.Now().UTC())
	// Place the meter at the configured boundary without writing a 256 MiB fixture.
	if _, err := s.db.Exec("UPDATE outbox_usage SET pending_bytes=?", MaxSpoolBytes); err != nil {
		t.Fatal(err)
	}
	if err := s.PersistObservation(ctx, event, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PersistObservation(ctx, event, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetEvent(ctx, event.ID); err != nil {
		t.Fatal(err)
	}
	if d, err := s.DeliveryStatus(ctx); err != nil || d.Pending != 0 || d.PendingBytes != MaxSpoolBytes || d.LostRecords != 1 {
		t.Fatalf("overflow: %+v %v", d, err)
	}
}

func TestOversizeBundleBeyondProtocolLimitPreservesLocalEvidence(t *testing.T) {
	ctx := context.Background()
	s := enrolledTestStore(t)
	event := testEvent("large-event", 1, time.Now().UTC())
	event.Process.Argv = []string{strings.Repeat("x", managed.MaxRecordBytes)}
	for i := 0; i < 2; i++ {
		if err := s.PersistObservation(ctx, event, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.GetEvent(ctx, event.ID); err != nil {
		t.Fatal(err)
	}
	if d, err := s.DeliveryStatus(ctx); err != nil || d.LostRecords != 1 || d.Pending != 0 || d.PendingBytes != 0 {
		t.Fatalf("oversized valid local event: %+v %v", d, err)
	}
}

func TestCapacityEphemeralAndCappedBacklog(t *testing.T) {
	ctx := context.Background()
	s, err := OpenEphemeral(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DeliveryStatus(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unenrolled: %v", err)
	}
	if _, err := s.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?)
INSERT INTO events(event_id,schema_version,event_time_ns,ingest_time_ns,event_type,event_json) SELECT 'old-'||i,'0.1',i,i,'test','{}' FROM n`, backlogScanLimit+3); err != nil {
		t.Fatal(err)
	}
	c, err := s.Capacity(ctx, time.Now(), time.Now())
	if err != nil || c.DatabaseBytes != nil || c.WALBytes != nil || c.DiskAvailableBytes != nil || !c.BacklogTruncated || c.RetentionBacklog != backlogScanLimit {
		t.Fatalf("bounded sample: %+v %v", c, err)
	}
}
