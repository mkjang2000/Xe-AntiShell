package storage

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestStableSourceEventRetryIgnoresAncestorObservationTimes(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	event := sourceEventWithAncestors()
	if inserted, err := store.SaveEventResult(ctx, event); err != nil || !inserted {
		t.Fatalf("initial SaveEventResult() = (%v, %v)", inserted, err)
	}
	retry := copySourceEvent(t, event)
	retry.Sequence++
	retry.IngestTime = retry.IngestTime.Add(time.Minute)
	retry.Process.FirstSeen = retry.Process.FirstSeen.Add(time.Minute)
	retry.Process.LastSeen = retry.Process.LastSeen.Add(time.Minute)
	for index := range retry.Ancestors {
		retry.Ancestors[index].FirstSeen = retry.Ancestors[index].FirstSeen.Add(time.Minute)
		retry.Ancestors[index].LastSeen = retry.Ancestors[index].LastSeen.Add(time.Minute)
	}
	wantRetry := copySourceEvent(t, retry)
	if inserted, err := store.SaveEventResult(ctx, retry); err != nil || inserted {
		t.Fatalf("retry SaveEventResult() = (%v, %v), want duplicate", inserted, err)
	}
	if !reflect.DeepEqual(retry, wantRetry) {
		t.Fatal("duplicate comparison changed the caller's observation")
	}
	stored, err := store.GetEvent(ctx, event.ID)
	if err != nil || !reflect.DeepEqual(stored, event) {
		t.Fatalf("retry changed the original durable event: %+v, %v", stored, err)
	}

	changedSource := copySourceEvent(t, retry)
	changedSource.Ancestors[0].StartTime = changedSource.Ancestors[0].StartTime.Add(time.Nanosecond)
	if _, err := store.SaveEventResult(ctx, changedSource); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed ancestor source time error = %v, want ErrConflict", err)
	}
}

func TestSameSourceEventDoesNotMutateSharedAncestorStorage(t *testing.T) {
	left := sourceEventWithAncestors()
	right := copySourceEvent(t, left)
	shared := []model.Process{left.Ancestors[0], right.Ancestors[0]}
	shared[1].FirstSeen = shared[1].FirstSeen.Add(time.Minute)
	shared[1].LastSeen = shared[1].LastSeen.Add(time.Minute)
	left.Ancestors, right.Ancestors = shared[:1], shared[1:]
	wantLeft, wantRight := copySourceEvent(t, left), copySourceEvent(t, right)
	wantShared := append([]model.Process(nil), shared...)
	if !sameSourceEvent(left, right) {
		t.Fatal("observation times changed source identity")
	}
	if !reflect.DeepEqual(left, wantLeft) || !reflect.DeepEqual(right, wantRight) || !reflect.DeepEqual(shared, wantShared) {
		t.Fatal("source comparison mutated caller-owned or shared ancestor storage")
	}
}

func TestSameSourceEventRetainsSourceIdentityAndLifecycle(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*model.Event)
	}{
		{"event time", func(event *model.Event) { event.EventTime = event.EventTime.Add(time.Nanosecond) }},
		{"source ID", func(event *model.Event) { event.SourceEventID += "-changed" }},
		{"event ID", func(event *model.Event) { event.ID += "-changed" }},
		{"boot ID", func(event *model.Event) { event.BootID += "-changed" }},
		{"process start", func(event *model.Event) { event.Process.StartTime = event.Process.StartTime.Add(time.Nanosecond) }},
		{"process exit", func(event *model.Event) {
			at := event.Process.ExitedAt.Add(time.Nanosecond)
			event.Process.ExitedAt = &at
		}},
		{"process exec ID", func(event *model.Event) { event.Process.ExecID += "-changed" }},
		{"process argv", func(event *model.Event) { event.Process.Argv[0] = "changed" }},
		{"ancestor start", func(event *model.Event) {
			event.Ancestors[0].StartTime = event.Ancestors[0].StartTime.Add(time.Nanosecond)
		}},
		{"ancestor exit", func(event *model.Event) {
			at := event.Ancestors[0].ExitedAt.Add(time.Nanosecond)
			event.Ancestors[0].ExitedAt = &at
		}},
		{"ancestor exit omitted", func(event *model.Event) { event.Ancestors[0].ExitedAt = nil }},
		{"ancestor key", func(event *model.Event) { event.Ancestors[0].Key += "-changed" }},
		{"ancestor exec ID", func(event *model.Event) { event.Ancestors[0].ExecID += "-changed" }},
		{"ancestor argv", func(event *model.Event) { event.Ancestors[0].Argv[0] = "changed" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := sourceEventWithAncestors()
			changed := copySourceEvent(t, original)
			test.change(&changed)
			if sameSourceEvent(original, changed) {
				t.Fatal("changed source data was accepted as the same event")
			}
		})
	}
}

func sourceEventWithAncestors() model.Event {
	event := testEvent("stable-source-with-parent", 10, time.Unix(100, 0).UTC())
	event.SourceEventID = "exec:source-child"
	event.Process.ExecID = "source-child"
	exited := event.EventTime.Add(time.Second)
	event.Process.ExitedAt = &exited
	parent := testProcess("source-parent", 42, event.EventTime.Add(-time.Minute))
	parent.ExecID = "source-parent"
	parent.ExitedAt = &exited
	event.Ancestors = []model.Process{parent}
	return event
}

func copySourceEvent(t *testing.T, event model.Event) model.Event {
	t.Helper()
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var copied model.Event
	if err := json.Unmarshal(encoded, &copied); err != nil {
		t.Fatal(err)
	}
	return copied
}
