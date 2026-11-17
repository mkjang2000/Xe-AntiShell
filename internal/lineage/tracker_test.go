package lineage

import (
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestObserveBuildsParentAndSeparatesPIDReuse(t *testing.T) {
	now := time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)
	tracker := New()
	parentEvent := model.Event{
		BootID: "boot-1", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 10, PPID: 1, ExecID: "parent", Exe: "/usr/sbin/nginx"},
	}
	parent := tracker.Observe(&parentEvent)
	childEvent := model.Event{
		BootID: "boot-1", EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second),
		Process: model.Process{PID: 20, PPID: 10, Exe: "/bin/sh"},
	}
	child := tracker.Observe(&childEvent)
	if child.ParentKey != parent.Key || !child.Complete {
		t.Fatalf("child parent not resolved: %+v, parent=%s", child, parent.Key)
	}

	reusedEvent := model.Event{
		BootID: "boot-1", EventTime: now.Add(2 * time.Second), IngestTime: now.Add(2 * time.Second),
		Process: model.Process{PID: 20, PPID: 10, Exe: "/bin/bash"},
	}
	reused := tracker.Observe(&reusedEvent)
	if reused.Key == child.Key {
		t.Fatal("PID reuse produced the same process key")
	}
}

func TestUnknownParentStaysIncomplete(t *testing.T) {
	now := time.Now().UTC()
	tracker := New()
	event := model.Event{
		BootID: "boot-1", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 42, PPID: 9999, Exe: "/bin/sh"},
	}
	process := tracker.Observe(&event)
	if process.Complete || process.ParentKey != "" || process.LineageConfidence != model.LineageUnknown {
		t.Fatalf("unknown parent was presented as known: %+v", process)
	}
}

func TestRestorePrefersMostRecentlySeenEqualStartTime(t *testing.T) {
	tracker := New()
	started := time.Unix(100, 123_000_000).UTC()
	older := model.Process{
		Key: "proc-old", PID: 42, StartTime: started,
		FirstSeen: started, LastSeen: started.Add(time.Millisecond),
	}
	newer := model.Process{
		Key: "proc-new", PID: 42, StartTime: started,
		FirstSeen: started, LastSeen: started.Add(2 * time.Millisecond),
	}

	// Restore in reverse recency order to prove selection does not depend on
	// database iteration order.
	tracker.Restore([]model.Process{newer, older})
	current, ok := tracker.CurrentByPID(42)
	if !ok || current.Key != newer.Key {
		t.Fatalf("current equal-time process = %#v, want %q", current, newer.Key)
	}
}

func TestObserveInheritsOriginThroughExplicitParentKey(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	parent := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 100, PPID: 1, ExecID: "parent-exec", Exe: "/usr/bin/python3", OriginService: "orders.service"},
	}
	tracker.Observe(&parent)
	child := model.Event{
		BootID: "boot", EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second),
		Process: model.Process{PID: 101, PPID: 100, ExecID: "child-exec", ParentKey: parent.Process.Key, Exe: "/usr/bin/bash", LineageConfidence: model.LineageVerified},
	}
	tracker.Observe(&child)
	if child.Process.OriginService != "orders.service" || child.Process.ParentKey != parent.Process.Key {
		t.Fatalf("explicit parent origin was not inherited: %+v", child.Process)
	}
}

func TestExplicitMissingParentDoesNotInheritFromReusedPID(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	parent := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 100, PPID: 1, ExecID: "new-parent", OriginService: "orders.service"},
	}
	tracker.Observe(&parent)
	child := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 101, PPID: 100, ExecID: "child-exec", ParentKey: "proc-old-parent", LineageConfidence: model.LineageUnknown},
	}
	tracker.Observe(&child)
	if child.Process.OriginService != "" || child.Process.Complete {
		t.Fatalf("missing parent inherited reused PID context: %+v", child.Process)
	}
}

func TestBoundedTrackerEvictsExitedContextBeforeLiveContext(t *testing.T) {
	tracker := NewBounded(2)
	now := time.Now().UTC()
	first := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 10, ExecID: "first"}}
	second := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 20, ExecID: "second"}}
	tracker.Observe(&first)
	tracker.Observe(&second)
	if _, ok := tracker.Exit(second.Process.Key, 20, now.Add(time.Second)); !ok {
		t.Fatal("second process was not exited")
	}
	third := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 30, ExecID: "third"}}
	tracker.Observe(&third)
	if _, ok := tracker.Get(first.Process.Key); !ok {
		t.Fatal("live context was evicted before exited context")
	}
	if _, ok := tracker.Get(second.Process.Key); ok {
		t.Fatal("exited context remained above bound")
	}
	if len(tracker.byKey) != 2 || len(tracker.entries) != 2 || tracker.recency.Len() != 2 {
		t.Fatalf("bounded indexes disagree: keys=%d entries=%d recency=%d", len(tracker.byKey), len(tracker.entries), tracker.recency.Len())
	}
}

func TestBoundedTrackerEvictionDoesNotRemoveReusedPID(t *testing.T) {
	tracker := NewBounded(2)
	now := time.Now().UTC()
	old := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 10, ExecID: "old"}}
	reused := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 10, ExecID: "new"}}
	third := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 30, ExecID: "third"}}
	tracker.Observe(&old)
	tracker.Observe(&reused)
	tracker.Observe(&third)
	current, ok := tracker.CurrentByPID(10)
	if !ok || current.ExecID != "new" {
		t.Fatalf("old key eviction removed current PID record: %+v exists=%v", current, ok)
	}
	if _, ok := tracker.Get(old.Process.Key); ok {
		t.Fatal("old context was not evicted")
	}
}

func TestBoundedTrackerStopsAtEvictedAncestor(t *testing.T) {
	tracker := NewBounded(1)
	now := time.Now().UTC()
	parent := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 10, ExecID: "parent"}}
	tracker.Observe(&parent)
	child := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 20, ExecID: "child", ParentKey: parent.Process.Key}}
	tracker.Observe(&child)
	if got := tracker.Ancestors(child.Process.Key, 64); len(got) != 0 {
		t.Fatalf("evicted ancestry was fabricated: %+v", got)
	}
	if _, ok := tracker.CurrentByPID(10); ok {
		t.Fatal("evicted parent remained current")
	}
}

func TestContextCannotReviveExitedProcess(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	event := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 10, ExecID: "old"}}
	tracker.Observe(&event)
	tracker.Exit(event.Process.Key, 10, now.Add(time.Second))
	context := event.Process
	context.LastSeen = now.Add(time.Minute)
	context.ExitedAt = nil
	observed := tracker.ObserveContext(context)
	if observed.ExitedAt == nil {
		t.Fatal("delayed context lost the previously observed exit")
	}
	if _, exists := tracker.CurrentByPID(10); exists {
		t.Fatal("delayed context revived an exited PID")
	}
}

func TestContextCannotReplaceNewerPIDExecution(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	event := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 10, ExecID: "new", StartTime: now}}
	tracker.Observe(&event)
	older := model.Process{Key: "proc-old", ExecID: "old", PID: 10, StartTime: now.Add(-time.Minute), LastSeen: now.Add(time.Minute)}
	tracker.ObserveContext(older)
	current, exists := tracker.CurrentByPID(10)
	if !exists || current.ExecID != "new" {
		t.Fatalf("old ancestor context replaced newer PID owner: %+v", current)
	}
}

func TestContextInheritsExactParentWithoutExecutionEvent(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	parent := model.Process{Key: "proc-parent", ExecID: "parent", PID: 10, StartTime: now, OriginService: "orders.service"}
	tracker.ObserveContext(parent)
	child := model.Process{Key: "proc-child", ExecID: "child", PID: 20, PPID: -1, StartTime: now, ParentKey: parent.Key}
	child = tracker.ObserveContext(child)
	if child.OriginService != parent.OriginService || child.PPID != parent.PID || !child.Complete {
		t.Fatalf("context did not link exact parent: %+v", child)
	}
}
