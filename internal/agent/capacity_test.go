package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestStatusCapacityQueueCommitsAndDropReasons(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) {
		c.Limits.QueueSize = 1
		c.Privacy.StoreRawEvents = true
	})
	defer store.Close()
	s.accepting = true // Exercise a full bounded queue without starting consumers.
	valid := model.Event{ID: "saved", Type: "test", Source: "test", EventTime: time.Now().UTC()}
	for _, e := range []model.Event{valid, valid, {ID: strings.Repeat("a", s.config.Limits.MaxEventBytes)}, {RawJSON: json.RawMessage("invalid")}} {
		if err := s.Submit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	queued := <-s.eventQueue
	s.processQueuedEvent(queued)
	s.processQueuedEvent(queuedEvent{Event: model.Event{}})
	s.recordProcessingFailure(errors.New("test persistence error"))
	s.recordProcessingFailure(&eventProcessingError{operation: "response", cause: errors.New("post-commit")})
	status, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d := status.CapabilityReport.Capabilities[storageCapacity].Details
	for k, want := range map[string]string{"queue_depth": "0", "queue_capacity": "1", "queue_high_water": "1",
		"drop_encode": "1", "drop_oversize": "1", "drop_queue_timeout": "1", "drop_invalid": "1", "drop_storage": "1", "drop_shutdown": "0",
		"stored_events_today": "1", "retention_backlog_events": "0", "observation_history_minutes": "0", "compact_observations": "false"} {
		if got := d[k]; got != want {
			t.Errorf("%s=%s want %s", k, got, want)
		}
	}
	if status.Dropped != 5 || d["pending_records"] != "" {
		t.Errorf("standalone drops/delivery: %d %+v", status.Dropped, d)
	}
	if latency, err := strconv.ParseFloat(d["last_store_latency_ms"], 64); err != nil || latency < 500 || d["max_store_latency_ms"] != d["last_store_latency_ms"] {
		t.Fatalf("submit-to-commit latency: %+v", d)
	}
	if err := store.SaveManagedState(ctx, storage.ManagedState{AgentID: "agent", EnrollmentID: "enroll", KeyPEM: "test"}); err != nil {
		t.Fatal(err)
	}
	status, err = s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := managed.Heartbeat{AgentID: "agent", Status: status}
	payload, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var received managed.Heartbeat
	if err := managed.DecodeStrict(payload, 1<<20, &received); err != nil {
		t.Fatal(err)
	}
	d = received.Status.CapabilityReport.Capabilities[storageCapacity].Details
	if d["pending_records"] != "0" || d["pending_bytes"] != "0" || d["spool_limit_bytes"] != strconv.Itoa(storage.MaxSpoolBytes) || d["disconnect_at"] != "" {
		t.Fatalf("managed heartbeat: %+v", d)
	}
}
