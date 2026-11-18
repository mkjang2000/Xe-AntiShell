package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestObservationServiceUpgradeAndIndexPlans(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file::memory:?mode=memory&cache=private&_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if _, err := db.Exec("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, name TEXT, checksum TEXT, applied_at_ns INTEGER)"); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[:4] {
		if err := store.applyMigration(ctx, migration); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Unix(1500, 0).UTC()
	migrated := false
	save := func(id, kind, service string, sequence uint64, observed time.Time) model.Event {
		t.Helper()
		e := testEvent(id, sequence, observed)
		e.Type, e.Process.OriginService = kind, service
		if !migrated {
			// Seed the historic schema as the old agent would.
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(`INSERT INTO events (event_id,schema_version,event_time_ns,ingest_time_ns,event_type,event_json)
VALUES (?,?,?,?,?,?)`, e.ID, e.SchemaVersion, e.EventTime.UnixNano(), e.IngestTime.UnixNano(), e.Type, raw)
			if err != nil {
				t.Fatal(err)
			}
		} else if err := store.SaveEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	save("other", "process.exec", "web.service", 1, at)
	save("a", "file.write", "web.service", 2, at)
	save("b", "network.connect", "web.service", 3, at)
	save("legacy-unknown", "network.connect", "", 4, at)
	if err := store.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	migrated = true

	// Check the actual backfill statement embedded in the migration, including
	// the distinction between scanning an index and seeking the two type ranges.
	start := strings.Index(migrations[4].sql, "INSERT INTO observation_services(")
	if start < 0 {
		t.Fatal("missing observation backfill")
	}
	backfill, _, ok := strings.Cut(migrations[4].sql[start:], ";")
	if !ok {
		t.Fatal("incomplete backfill statement")
	}
	plan := storageQueryPlan(t, db, backfill)
	if !strings.Contains(plan, "SEARCH events USING INDEX events_type_time_idx (event_type=?)") ||
		strings.Contains(plan, "SCAN events") {
		t.Fatalf("unbounded observation backfill: %s", plan)
	}
	plan = storageQueryPlan(t, db, observationSamplesByService, "web.service", 2)
	if !strings.Contains(plan, "observations_service_time_idx (service=?)") ||
		!strings.Contains(plan, "SEARCH e USING INDEX") || strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("unindexed service lookup or sort: %s", plan)
	}

	// Same contents and identity on retry must leave the indexed service and
	// original order intact. A failed event/finding write must leave no row.
	newer := save("newer", "file.write", "web.service", 5, at.Add(time.Second))
	if err := store.SaveEvent(ctx, newer); err != nil {
		t.Fatal(err)
	}
	save("new-unknown", "file.write", "", 6, at.Add(time.Second))
	save("ignored", "process.exit", "web.service", 7, at.Add(time.Second))
	bad := testEvent("rollback", 8, at)
	bad.Type, bad.Process.OriginService = "network.connect", "web.service"
	finding := managedTestFinding(bad)
	finding.EvidenceEventIDs = []string{"missing"}
	if err := store.PersistObservation(ctx, bad, []model.Finding{finding}); err == nil {
		t.Fatal("expected observation rollback")
	}
	checkIDs := func(service string, limit int, want ...string) {
		t.Helper()
		report, err := store.ObservationSamples(ctx, model.ObservationQuery{Service: service, Limit: limit})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, sample := range report.Samples {
			got = append(got, sample.EventID)
			if service != "" && sample.Service != service {
				t.Fatalf("wrong immutable service: %+v", sample)
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%q samples: got %v, want %v", service, got, want)
		}
	}
	checkIDs("web.service", 2, "newer", "b")
	checkIDs("web.service", 10, "newer", "b", "a")
	checkIDs("unknown", 10, "new-unknown", "legacy-unknown")
	checkIDs("absent.service", 10)
	checkIDs("", 10, "newer", "new-unknown", "legacy-unknown", "b", "a")
	if n, err := store.DeleteEventsBefore(ctx, at.Add(time.Second), 10); err != nil || n != 4 {
		t.Fatalf("retention count %d: %v", n, err)
	}
	checkIDs("web.service", 10, "newer")
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM observation_services").Scan(&count); err != nil || count != 2 {
		t.Fatalf("projection after retention/rollback: got %d rows, err %v", count, err)
	}
}

func storageQueryPlan(t *testing.T, db *sql.DB, stmt string, args ...any) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+stmt, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(details, "\n")
}
