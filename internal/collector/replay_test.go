package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestReplayJSONL(t *testing.T) {
	input := strings.Join([]string{
		`{"schema_version":"0.1","source":"test","event_type":"process.exec","event_time":"2026-01-01T00:00:00Z"}`,
		`{"schema_version":"0.1","source":"test","event_type":"process.exit","event_time":"2026-01-01T00:00:01Z"}`,
	}, "\n")
	replay := NewReplayJSONLReader("test", strings.NewReader(input), Metadata{HostID: "host", BootID: "boot"})
	var events []model.Event
	err := replay.Run(context.Background(), SinkFunc(func(_ context.Context, event model.Event) error {
		events = append(events, event)
		return nil
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].HostID != "host" || events[0].BootID != "boot" {
		t.Fatalf("metadata not applied: %+v", events[0])
	}
	if !events[0].EventTime.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected time: %v", events[0].EventTime)
	}
	health := replay.Health()
	if health.EventsReceived != 2 || health.EventsEmitted != 2 {
		t.Fatalf("unexpected health: %+v", health)
	}
}

func TestReplayRejectsMultipleValuesOnLine(t *testing.T) {
	replay := NewReplayJSONLReader("test", strings.NewReader(`{"event_type":"a"} {"event_type":"b"}`), Metadata{})
	if err := replay.Run(context.Background(), SinkFunc(func(context.Context, model.Event) error { return nil })); err == nil {
		t.Fatal("Run() error = nil, want decoding error")
	}
}
