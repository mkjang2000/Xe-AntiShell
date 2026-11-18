package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"xe-antishell/internal/collector"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
)

type backoffTestCollector struct {
	runtimeTestCollector
	run func(context.Context, collector.EventSink) error
}

func (c *backoffTestCollector) Run(ctx context.Context, sink collector.EventSink) error {
	return c.run(ctx, sink)
}

func TestTetragonRetryBackoffAndResetAfterCommit(t *testing.T) {
	s, store := newTestService(t, config.CollectorTetragon, nil)
	defer store.Close()
	s.accepting = true
	calls := 0
	source := &backoffTestCollector{run: func(ctx context.Context, sink collector.EventSink) error {
		calls++
		if calls == 8 {
			event := model.Event{
				ID: "backoff-recovery", BootID: "boot-test", HostID: "host-test",
				Source: "tetragon", Type: "process.exec",
				Process: model.Process{PID: 200, ExecID: "after-retry", Exe: "/usr/bin/worker", EUID: 1000},
			}
			if err := sink.Submit(ctx, event); err != nil {
				t.Fatal(err)
			}
			select {
			case item := <-s.eventQueue:
				s.processQueuedEvent(item)
			default:
				t.Fatal("recovery event did not reach the queue")
			}
			if _, err := store.GetEvent(ctx, event.ID); err != nil {
				t.Fatalf("read committed recovery event: %v", err)
			}
		}
		if calls%2 == 0 {
			return errors.New("collector exited")
		}
		return nil // clean EOF is also a gap
	}}

	wantSeconds := []int{1, 2, 4, 8, 16, 30, 30, 1, 2}
	waits := 0
	s.runTetragon(context.Background(), source, func(_ context.Context, delay time.Duration) bool {
		if waits >= len(wantSeconds) {
			t.Fatal("collector kept retrying after wait returned false")
		}
		want := time.Duration(wantSeconds[waits]) * time.Second
		if delay != want {
			t.Fatalf("delay after subscription %d = %s, want %s", calls, delay, want)
		}
		waits++
		return waits < len(wantSeconds)
	})
	if waits != len(wantSeconds) || calls != waits {
		t.Fatalf("got %d subscriptions and %d waits, want %d each", calls, waits, len(wantSeconds))
	}
}
