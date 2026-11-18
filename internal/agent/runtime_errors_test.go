package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestPersistenceFailureRecoversOnlyAfterDurableObservation(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) { c.Collector.Audit.OnlyDetectionOrigins = true })
	defer store.Close()
	s.setRuntimeState(model.AgentModeActive, model.HealthHealthy, "test", nil)
	first := model.Event{ID: "persisted", Type: "security.test", Source: "test", EventTime: time.Now().UTC()}
	if err := s.processEvent(context.Background(), &first); err != nil {
		t.Fatal(err)
	}
	conflict := first
	conflict.Type = "security.changed"
	s.processQueuedEvent(queuedEvent{Event: conflict})
	failed, _ := s.Status(context.Background())
	if failed.Mode != model.AgentModeError || failed.Dropped != 1 || failed.LastError == "" {
		t.Fatalf("failure was hidden: %#v", failed)
	}
	// A filtered event and an invalid input provide no proof of recovered storage.
	s.processQueuedEvent(queuedEvent{Event: model.Event{Type: "process.exec", Source: "audit", Process: model.Process{PID: 881, PPID: 1, Exe: "/bin/sh"}}})
	s.processQueuedEvent(queuedEvent{Event: model.Event{Source: "test"}})
	stillFailed, _ := s.Status(context.Background())
	if stillFailed.LastError == "" || stillFailed.Mode != model.AgentModeError {
		t.Fatal("non-durable input cleared persistence failure")
	}
	s.processQueuedEvent(queuedEvent{Event: model.Event{ID: "recovered", Type: "security.test", Source: "test", EventTime: time.Now().UTC()}})
	recovered, _ := s.Status(context.Background())
	if recovered.Mode != model.AgentModeActive || recovered.Health != model.HealthHealthy || recovered.LastError != "" || recovered.Dropped != 2 {
		t.Fatalf("did not recover correctly: %#v", recovered)
	}
	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("unexpected evidence after recovery: count=%d err=%v", len(events), err)
	}
}

func TestPersistenceRecoveryPreservesIndependentFailures(t *testing.T) {
	for _, reason := range []string{"collector", "retention", "bootstrap", "response"} {
		t.Run(reason, func(t *testing.T) {
			s, store := newTestService(t, config.CollectorDisabled, nil)
			defer store.Close()
			s.setRuntimeState(model.AgentModeActive, model.HealthHealthy, "test", nil)
			s.setOperationError("event_store", errors.New("old storage failure"))
			switch reason {
			case "collector":
				s.setRuntimeState(model.AgentModeDegraded, model.HealthError, "test", errors.New("collector failed"))
			case "bootstrap":
				s.bootstrapErr = errors.New("bootstrap failed")
				s.setRuntimeState(model.AgentModeActive, model.HealthDegraded, "test", s.bootstrapErr)
			case "retention":
				s.recordOperationalError(errors.New("retention failed"))
			case "response":
				s.setOperationError("response", errors.New("response failed"))
			}
			s.processQueuedEvent(queuedEvent{Event: model.Event{ID: "saved", Type: "security.test", Source: "test", EventTime: time.Now().UTC()}})
			status, _ := s.Status(context.Background())
			if strings.Contains(status.LastError, "old storage failure") || !strings.Contains(status.LastError, reason+" failed") || status.Health == model.HealthHealthy || status.Dropped != 0 {
				t.Fatalf("wrong independent-error handling: %#v", status)
			}
			if reason == "collector" && status.Health != model.HealthError {
				t.Fatal("collector error was downgraded after storage recovery")
			}
		})
	}
}

func TestRetentionStartupDeferralCancelsWithoutDatabaseAccess(t *testing.T) {
	// A nil store would panic if the retention loop ran its initial database pass.
	s := &Service{}
	ctx, cancel := context.WithCancel(context.Background())
	s.producerWG.Add(1)
	done := make(chan struct{})
	go func() { s.retentionLoop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked by retention startup wait")
	}
	s.producerWG.Wait()
}

func TestLateCommitCannotRecoverDisconnectedSubscription(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	ctx := context.Background()
	s.setRuntimeState(model.AgentModeActive, model.HealthHealthy, "tetragon-json", nil)
	s.recordCollectorDisconnect(errors.New("disconnected"))

	old := model.Event{ID: "queued-before-gap", BootID: "boot", Source: "tetragon", Type: "process.exec",
		Process: model.Process{PID: 50, ExecID: "old", Exe: "/bin/worker", OriginService: "old.service"}}
	s.processQueuedEvent(queuedEvent{Event: old})
	if _, err := store.GetEvent(ctx, old.ID); err != nil {
		t.Fatalf("queued evidence was lost: %v", err)
	}
	if !s.runtimeEvidence["tetragon"].ExecAt.IsZero() || !s.recovery.recoveredAt.IsZero() {
		t.Fatal("late event from a disconnected subscription claimed live monitoring")
	}

	next := model.Event{ID: old.ID, BootID: "boot", Source: "tetragon", Type: "process.exec",
		Process: model.Process{PID: 51, PPID: 50, ExecID: "new", Exe: "/bin/worker"}}
	s.processQueuedEvent(queuedEvent{Event: next, generation: 1})
	if s.operationErrors["event_store"] == "" || !s.recovery.recoveredAt.IsZero() {
		t.Fatal("failed commit closed the collection gap")
	}
	next.ID = "stored-after-gap"
	s.recordOperationalError(errors.New("retention failed"))
	s.processQueuedEvent(queuedEvent{Event: next, generation: 1})
	saved, err := store.GetEvent(ctx, next.ID)
	if err != nil || saved.Process.ParentKey != "" || saved.Process.OriginService != "" {
		t.Fatalf("PID-only context crossed collection gap: %+v, %v", saved.Process, err)
	}
	if s.recovery.recoveredAt.IsZero() || s.operationErrors["event_store"] != "" {
		t.Fatal("successful commit did not restore collection")
	}
	status, _ := s.Status(ctx)
	if status.Health == model.HealthHealthy || status.LastError != "retention failed" {
		t.Fatalf("collection recovery hid independent failure: %+v", status)
	}
}

func TestPostCommitResponseFailureDoesNotCountAsDroppedEvidence(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	s.setRuntimeState(model.AgentModeActive, model.HealthHealthy, "test", nil)
	event := model.Event{ID: "before-response", Type: "security.test", Source: "test", EventTime: time.Now().UTC()}
	if err := s.processEvent(context.Background(), &event); err != nil {
		t.Fatal(err)
	}
	s.recordProcessingFailure(&eventProcessingError{operation: "response", cause: errors.New("response audit failed")})
	status, _ := s.Status(context.Background())
	if status.Dropped != 0 || status.Health != model.HealthError || !strings.Contains(status.LastError, "response audit failed") {
		t.Fatalf("wrong post-commit failure accounting: %#v", status)
	}
	if _, err := store.GetEvent(context.Background(), event.ID); err != nil {
		t.Fatal("committed evidence disappeared", err)
	}
}
