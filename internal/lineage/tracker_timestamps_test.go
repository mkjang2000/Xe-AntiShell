package lineage

import (
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestObservePreservesObservationEnvelopeAcrossDelayedExecs(t *testing.T) {
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	tracker := New()
	event := model.Event{
		BootID: "boot", EventTime: base, IngestTime: base.Add(10 * time.Second),
		Process: model.Process{PID: 10, ExecID: "same-execution", StartTime: base},
	}
	tracker.Observe(&event)
	for _, seconds := range []int{8, 12, 9, 12} {
		event.IngestTime = base.Add(time.Duration(seconds) * time.Second)
		// A delayed delivery supplies its own observation times, rather than
		// the previous summary returned by Observe.
		event.Process.FirstSeen, event.Process.LastSeen = event.IngestTime, event.IngestTime
		process := tracker.Observe(&event)
		wantLast := base.Add(12 * time.Second)
		if seconds == 8 {
			wantLast = base.Add(10 * time.Second)
		}
		assertObservationBounds(t, process, base.Add(8*time.Second), wantLast)
		if !event.EventTime.Equal(base) || !process.StartTime.Equal(base) {
			t.Fatal("observation ordering changed source timestamps")
		}
	}
}

func TestObserveHandlesSourceTimeAheadOfObservation(t *testing.T) {
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	sourceAt, observedAt := base.Add(10*time.Second), base.Add(3*time.Second)
	for _, legacy := range []bool{false, true} {
		name := "observation-times"
		if legacy {
			name = "legacy-source-times"
		}
		t.Run(name, func(t *testing.T) {
			tracker := New()
			initialBound := observedAt
			if legacy {
				initialBound = sourceAt
			}
			event := model.Event{
				BootID: "boot", EventTime: sourceAt, IngestTime: observedAt,
				Process: model.Process{PID: 10, ExecID: "future-source", StartTime: sourceAt, FirstSeen: initialBound, LastSeen: initialBound},
			}
			process := tracker.Observe(&event)
			assertObservationBounds(t, process, observedAt, initialBound)
			if !event.EventTime.Equal(sourceAt) || !process.StartTime.Equal(sourceAt) || process.ExitedAt != nil {
				t.Fatal("source lifecycle times were changed to match the observation clock")
			}
		})
	}
}

func TestDelayedExitAfterAncestorObservationKeepsFurtherContextValid(t *testing.T) {
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	tracker := New()
	parent := model.Process{
		Key: "parent", ExecID: "parent-exec", PID: 10, StartTime: base,
		FirstSeen: base.Add(10 * time.Second), LastSeen: base.Add(10 * time.Second),
	}
	tracker.ObserveContext(parent)
	exitedAt, observedAt := base.Add(5*time.Second), base.Add(12*time.Second)
	closed, ok := tracker.ExitObserved(parent.Key, parent.PID, exitedAt, observedAt)
	if !ok {
		t.Fatal("ancestor context was not available for the delayed exit")
	}
	assertObservationBounds(t, closed, parent.FirstSeen, observedAt)
	if closed.ExitedAt == nil || !closed.ExitedAt.Equal(exitedAt) || !closed.StartTime.Equal(parent.StartTime) {
		t.Fatal("delayed exit changed source lifecycle timestamps")
	}
	parent.FirstSeen, parent.LastSeen = base.Add(13*time.Second), base.Add(13*time.Second)
	context := tracker.ObserveContext(parent)
	assertObservationBounds(t, context, closed.FirstSeen, parent.LastSeen)
	if context.ExitedAt == nil || !context.ExitedAt.Equal(exitedAt) {
		t.Fatal("later ancestor observation lost the known exit")
	}
	if _, exists := tracker.CurrentByPID(parent.PID); exists {
		t.Fatal("later ancestor observation revived the exited process")
	}
	child := model.Event{
		BootID: "boot", EventTime: base.Add(14 * time.Second), IngestTime: base.Add(15 * time.Second),
		Process: model.Process{PID: 20, ExecID: "child", ParentKey: parent.Key},
	}
	tracker.Observe(&child)
	ancestors := tracker.Ancestors(child.Process.Key, 64)
	if len(ancestors) != 1 || ancestors[0].LastSeen.Before(ancestors[0].FirstSeen) || ancestors[0].ExitedAt == nil {
		t.Fatalf("later child inherited invalid lifecycle context: %#v", ancestors)
	}
}

func TestExitObservedHandlesBackwardsClockAndRepeatedDelivery(t *testing.T) {
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	tracker := New()
	event := model.Event{
		BootID: "boot", EventTime: base, IngestTime: base.Add(10 * time.Second),
		Process: model.Process{PID: 10, ExecID: "execution", StartTime: base},
	}
	tracker.Observe(&event)
	exitedAt := base.Add(5 * time.Second)
	for _, test := range []struct{ observed, first, last int }{
		{7, 7, 10}, {6, 6, 10}, {13, 6, 13}, {7, 6, 13},
	} {
		process, ok := tracker.ExitObserved(event.Process.Key, event.Process.PID, exitedAt, base.Add(time.Duration(test.observed)*time.Second))
		if !ok {
			t.Fatal("repeated exit could not resolve the stable identity")
		}
		assertObservationBounds(t, process, base.Add(time.Duration(test.first)*time.Second), base.Add(time.Duration(test.last)*time.Second))
		if process.ExitedAt == nil || !process.ExitedAt.Equal(exitedAt) || !process.StartTime.Equal(base) {
			t.Fatal("clock change altered source lifecycle timestamps")
		}
	}
}

func TestExitObservationKeepsNewerPIDOwner(t *testing.T) {
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	tracker := New()
	older := model.Event{BootID: "boot", EventTime: base, IngestTime: base.Add(time.Second), Process: model.Process{PID: 10, ExecID: "old", StartTime: base}}
	tracker.Observe(&older)
	newer := model.Event{BootID: "boot", EventTime: base.Add(2 * time.Second), IngestTime: base.Add(3 * time.Second), Process: model.Process{PID: 10, ExecID: "new", StartTime: base.Add(2 * time.Second)}}
	tracker.Observe(&newer)
	closed, ok := tracker.ExitObserved(older.Process.Key, 10, base.Add(time.Second), base.Add(4*time.Second))
	if !ok {
		t.Fatal("older execution was missing")
	}
	closed.ExitedAt = nil
	closed.FirstSeen, closed.LastSeen = base.Add(5*time.Second), base.Add(5*time.Second)
	context := tracker.ObserveContext(closed)
	if context.ExitedAt == nil {
		t.Fatal("delayed source context revived the old identity")
	}
	current, ok := tracker.CurrentByPID(10)
	if !ok || current.Key != newer.Process.Key {
		t.Fatalf("delayed old exit/context replaced the newer PID owner: %#v", current)
	}
}

func TestObservationEnvelopeHandlesLegacyAndMissingBounds(t *testing.T) {
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	for _, bounds := range [][2]time.Time{{base.Add(10 * time.Second), base.Add(8 * time.Second)}, {{}, base.Add(10 * time.Second)}, {base.Add(10 * time.Second), {}}} {
		tracker := New()
		process := tracker.ObserveContext(model.Process{Key: "legacy", PID: 10, StartTime: base, FirstSeen: bounds[0], LastSeen: bounds[1]})
		if process.FirstSeen.IsZero() || process.LastSeen.Before(process.FirstSeen) {
			t.Fatalf("legacy observation bounds remained invalid: %#v", process)
		}
		closed, ok := tracker.Exit(process.Key, process.PID, base.Add(5*time.Second))
		if !ok {
			t.Fatal("compatibility exit did not resolve the process")
		}
		assertObservationBounds(t, closed, base.Add(5*time.Second), base.Add(10*time.Second))
		if closed.ExitedAt == nil || !closed.ExitedAt.Equal(base.Add(5*time.Second)) {
			t.Fatal("compatibility exit changed the source exit time")
		}
	}
}

func assertObservationBounds(t *testing.T, process model.Process, firstSeen, lastSeen time.Time) {
	t.Helper()
	if !process.FirstSeen.Equal(firstSeen) || !process.LastSeen.Equal(lastSeen) {
		t.Fatalf("observation bounds = [%s, %s], want [%s, %s]", process.FirstSeen, process.LastSeen, firstSeen, lastSeen)
	}
}
