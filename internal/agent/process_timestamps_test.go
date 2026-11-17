package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/collector"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestTetragonFutureSourceTimePersistsObservationClock(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	enableTimestampDelivery(t, store)
	observed := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	source := observed.Add(time.Nanosecond)
	parent := timestampSourceProcess{ExecID: "future-parent", PID: 100, Binary: "/usr/bin/python3", StartTime: observed.Add(-time.Second)}
	process := timestampSourceProcess{ExecID: "future-child", ParentExecID: parent.ExecID, PID: 101, Binary: "/usr/bin/true", StartTime: source}
	event := normalizedTimestampEvent(t, "process_exec", source, observed, process, &parent)
	if err := service.processEvent(context.Background(), &event); err != nil {
		t.Fatalf("source clock ahead by 1ns rejected the observation: %v", err)
	}
	stored, err := store.GetEvent(context.Background(), event.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.EventTime.Equal(source) || !stored.Process.StartTime.Equal(source) {
		t.Fatalf("source timestamps changed: %+v", stored)
	}
	for _, process := range append(append([]model.Process(nil), stored.Ancestors...), stored.Process) {
		assertTimestampEnvelope(t, process)
		if !process.FirstSeen.Equal(observed) || !process.LastSeen.Equal(observed) {
			t.Fatalf("source time leaked into observation bounds: %+v", process)
		}
		row, err := store.GetProcess(context.Background(), process.Key)
		if err != nil || !reflect.DeepEqual(row, process) {
			t.Fatalf("durable process differs from its evidence: %+v, %v", row, err)
		}
	}
	bundles, _ := timestampBundles(t, store)
	if len(bundles) != 1 || !reflect.DeepEqual(bundles[0].Event, stored) {
		t.Fatalf("delivery lost the source or observation timestamps: %+v", bundles)
	}
}

func TestTetragonDelayedParentExitDoesNotPoisonFollowingChildren(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	enableTimestampDelivery(t, store)
	ctx := context.Background()
	base := time.Date(2026, 11, 17, 1, 2, 0, 0, time.UTC)
	parent := timestampSourceProcess{ExecID: "delayed-parent", PID: 200, Binary: "/usr/bin/python3", StartTime: base.Add(time.Second)}
	firstChild := timestampSourceProcess{ExecID: "first-child", ParentExecID: parent.ExecID, PID: 201, Binary: "/usr/bin/true", StartTime: base.Add(5 * time.Second)}
	first := normalizedTimestampEvent(t, "process_exec", firstChild.StartTime, base.Add(5*time.Second), firstChild, &parent)
	if err := service.processEvent(ctx, &first); err != nil {
		t.Fatal(err)
	}
	exitedAt := base.Add(4 * time.Second)
	exit := normalizedTimestampEvent(t, "process_exit", exitedAt, base.Add(7*time.Second), parent, nil)
	if err := service.processEvent(ctx, &exit); err != nil {
		t.Fatalf("delayed parent exit rejected valid observation bounds: %v", err)
	}
	secondChild := timestampSourceProcess{ExecID: "second-child", ParentExecID: parent.ExecID, PID: 202, Binary: "/usr/bin/true", StartTime: base.Add(8 * time.Second)}
	second := normalizedTimestampEvent(t, "process_exec", secondChild.StartTime, base.Add(8*time.Second), secondChild, &parent)
	if err := service.processEvent(ctx, &second); err != nil {
		t.Fatalf("the delayed exit poisoned subsequent ancestry: %v", err)
	}
	row, err := store.GetProcess(ctx, first.Process.ParentKey)
	if err != nil {
		t.Fatal(err)
	}
	assertTimestampEnvelope(t, row)
	if !row.StartTime.Equal(parent.StartTime) || row.ExitedAt == nil || !row.ExitedAt.Equal(exitedAt) ||
		!row.FirstSeen.Equal(base.Add(5*time.Second)) || !row.LastSeen.Equal(base.Add(7*time.Second)) {
		t.Fatalf("parent source lifecycle or observation envelope changed: %+v", row)
	}
	if _, current := service.lineage.CurrentByPID(parent.PID); current {
		t.Fatal("a later child revived the exited parent")
	}
	storedExit, err := store.GetEvent(ctx, exit.ID)
	if err != nil || !storedExit.EventTime.Equal(exitedAt) || storedExit.Process.ExitedAt == nil || !storedExit.Process.ExitedAt.Equal(exitedAt) {
		t.Fatalf("source exit timestamp was not preserved: %+v, %v", storedExit, err)
	}
	bundles, _ := timestampBundles(t, store)
	if len(bundles) != 3 {
		t.Fatalf("accepted %d/3 observations for delivery", len(bundles))
	}
	for _, bundle := range bundles {
		if bundle.Event.ID == exit.ID && (!bundle.Event.EventTime.Equal(exitedAt) || bundle.Event.Process.ExitedAt == nil || !bundle.Event.Process.ExitedAt.Equal(exitedAt)) {
			t.Fatalf("delivery changed the original source exit time: %+v", bundle.Event)
		}
		for _, process := range append(append([]model.Process(nil), bundle.Event.Ancestors...), bundle.Event.Process) {
			assertTimestampEnvelope(t, process)
		}
	}
}

func TestTetragonSourceRetryAcrossFreshTrackerKeepsSingleDelivery(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, nil)
	defer func() {
		if store != nil {
			store.Close()
		}
	}()
	enableTimestampDelivery(t, store)
	ctx := context.Background()
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 17, 1, 2, 0, 0, time.UTC)
	parent := timestampSourceProcess{ExecID: "retry-parent", PID: 300, Binary: "/usr/bin/python3", StartTime: base}
	process := timestampSourceProcess{ExecID: "retry-child", ParentExecID: parent.ExecID, PID: 301, Binary: "/usr/bin/true", StartTime: base.Add(time.Second)}
	execAt, exitAt := base.Add(2*time.Second), base.Add(3*time.Second)
	first := normalizedTimestampEvent(t, "process_exec", execAt, base.Add(5*time.Second), process, &parent)
	exit := normalizedTimestampEvent(t, "process_exit", exitAt, base.Add(6*time.Second), process, &parent)
	for _, event := range []*model.Event{&first, &exit} {
		if err := service.processEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	before, beforeRecords := timestampBundles(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.Open(ctx, cfg.Agent.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	service, err = NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	retry := normalizedTimestampEvent(t, "process_exec", execAt, base.Add(15*time.Second), process, &parent)
	retryExit := normalizedTimestampEvent(t, "process_exit", exitAt, base.Add(16*time.Second), process, &parent)
	for _, event := range []*model.Event{&retry, &retryExit} {
		if err := service.processEvent(ctx, event); err != nil {
			t.Fatalf("stable source retry with a fresh tracker was not idempotent: %v", err)
		}
	}
	after, afterRecords := timestampBundles(t, store)
	if len(before) != 2 || len(after) != 2 || !reflect.DeepEqual(before, after) {
		t.Fatalf("retry changed immutable source bundles: before=%+v after=%+v", before, after)
	}
	for index := range beforeRecords {
		if beforeRecords[index].Sequence != afterRecords[index].Sequence || !bytes.Equal(beforeRecords[index].Payload, afterRecords[index].Payload) {
			t.Fatal("retry changed delivery identity or immutable payload")
		}
	}
	events, err := store.ListEvents(ctx, storage.EventFilter{Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("source retry created duplicate events: %+v, %v", events, err)
	}
	row, err := store.GetProcess(ctx, first.Process.Key)
	if err != nil || row.ExitedAt == nil || !row.ExitedAt.Equal(exitAt) || !row.StartTime.Equal(process.StartTime) {
		t.Fatalf("retry changed source lifecycle: %+v, %v", row, err)
	}
	assertTimestampEnvelope(t, row)
}

type timestampSourceProcess struct {
	ExecID       string    `json:"exec_id"`
	ParentExecID string    `json:"parent_exec_id,omitempty"`
	PID          int       `json:"pid"`
	Binary       string    `json:"binary"`
	StartTime    time.Time `json:"start_time"`
	UID          uint32    `json:"uid"`
}

func normalizedTimestampEvent(t *testing.T, kind string, sourceTime, observedAt time.Time, process timestampSourceProcess, parent *timestampSourceProcess) model.Event {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"time": sourceTime, kind: map[string]any{"time": sourceTime, "process": process, "parent": parent}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := collector.NormalizeTetragonJSON(raw, observedAt, collector.Metadata{HostID: "timestamp-host", BootID: "timestamp-boot"})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func assertTimestampEnvelope(t *testing.T, process model.Process) {
	t.Helper()
	if process.FirstSeen.IsZero() || process.LastSeen.IsZero() || process.LastSeen.Before(process.FirstSeen) {
		t.Fatalf("invalid local observation envelope: %+v", process)
	}
}

func enableTimestampDelivery(t *testing.T, store *storage.Store) {
	t.Helper()
	state, _, _ := managedPolicyFixture(t)
	if err := store.SaveManagedState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
}

func timestampBundles(t *testing.T, store *storage.Store) ([]managed.EventBundle, []managed.Record) {
	t.Helper()
	batch, err := store.DeliveryBatch(context.Background(), 64)
	if err != nil {
		t.Fatal(err)
	}
	bundles := make([]managed.EventBundle, len(batch.Records))
	for index, record := range batch.Records {
		if record.Kind != managed.RecordKindEventBundle {
			t.Fatalf("unexpected delivery record kind: %q", record.Kind)
		}
		if err := json.Unmarshal(record.Payload, &bundles[index]); err != nil {
			t.Fatal(err)
		}
	}
	return bundles, batch.Records
}
