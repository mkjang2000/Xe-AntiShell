package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestNormalizeTetragonProcessExec(t *testing.T) {
	raw := []byte(`{
      "time":"2026-01-02T03:04:05Z",
      "process_exec":{
        "process":{"exec_id":"host:123:42","pid":42,"uid":1000,"cwd":"/var/www","binary":"/usr/bin/bash","arguments":"-c id","start_time":"2026-01-02T03:04:04.9Z"},
        "parent":{"exec_id":"host:100:10","pid":10,"binary":"/usr/sbin/php-fpm"}
      }
    }`)
	event, err := NormalizeTetragonJSON(raw, time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatalf("NormalizeTetragonJSON() error = %v", err)
	}
	if event.Type != "process.exec" || event.Process.ExecID != "host:123:42" || event.Process.PPID != 10 {
		t.Fatalf("unexpected event: %+v", event)
	}
	if event.Process.ParentKey == "" || event.Process.LineageConfidence != model.LineageVerified {
		t.Fatalf("parent lineage was not retained: %+v", event.Process)
	}
	if event.Completeness != model.CompletenessPartial {
		t.Fatalf("flattened arguments should be partial, got: %q", event.Completeness)
	}
	retry, err := NormalizeTetragonJSON(raw, time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if retry.ID != event.ID {
		t.Fatalf("stable source event IDs differ: %q != %q", retry.ID, event.ID)
	}
}

func TestNormalizeTetragonProcessExit(t *testing.T) {
	raw := []byte(`{"process_exit":{"process":{"exec_id":"host:123:42","pid":42,"binary":"/usr/bin/bash"},"status":137,"signal":"SIGKILL","time":"2026-01-02T03:05:05Z"}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{})
	if err != nil {
		t.Fatalf("NormalizeTetragonJSON() error = %v", err)
	}
	if event.Type != "process.exit" || event.SourceEventID == "" || event.Process.ExitedAt == nil {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestNormalizeTetragonExecObservationTimesUseIngestion(t *testing.T) {
	ingested := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, ahead := range []time.Duration{time.Nanosecond, 5 * time.Second} {
		t.Run(ahead.String(), func(t *testing.T) {
			sourceTime := ingested.Add(ahead)
			source := tetragonProcess{ExecID: "source:42", PID: 42, Binary: "/usr/bin/id", StartTime: sourceTime.Add(-time.Second)}
			parent := tetragonProcess{ExecID: "parent:41", ParentExecID: "ancestor:40", PID: 41, Binary: "/usr/bin/bash", StartTime: ingested.Add(-time.Minute)}
			ancestor := tetragonProcess{ExecID: "ancestor:40", PID: 40, Binary: "/usr/sbin/service", StartTime: ingested.Add(-time.Hour)}
			raw, err := json.Marshal(tetragonEnvelope{Time: sourceTime, ProcessExec: &tetragonProcessExec{
				Process: source, Parent: &parent, Ancestors: []tetragonProcess{ancestor},
			}})
			if err != nil {
				t.Fatal(err)
			}
			event, err := NormalizeTetragonJSON(raw, ingested, Metadata{BootID: "boot"})
			if err != nil {
				t.Fatal(err)
			}
			if !event.EventTime.Equal(sourceTime) || !event.Process.StartTime.Equal(source.StartTime) || event.Process.ExitedAt != nil {
				t.Fatalf("source lifecycle timestamps changed: %+v", event)
			}
			if event.SourceEventID != "exec:source:42" || !bytes.Equal(event.RawJSON, raw) || len(event.Ancestors) != 2 {
				t.Fatalf("source identity, raw payload, or ancestry changed: %+v", event)
			}
			for _, process := range append([]model.Process{event.Process}, event.Ancestors...) {
				if !process.FirstSeen.Equal(ingested) || !process.LastSeen.Equal(ingested) {
					t.Fatalf("observation times follow the source clock: %+v", process)
				}
			}
			if !event.Ancestors[0].StartTime.Equal(parent.StartTime) || !event.Ancestors[1].StartTime.Equal(ancestor.StartTime) {
				t.Fatal("ancestor source start times changed")
			}
			retryTime := ingested.Add(time.Minute)
			retry, err := NormalizeTetragonJSON(raw, retryTime, Metadata{BootID: "boot"})
			if err != nil {
				t.Fatal(err)
			}
			if retry.ID != event.ID || retry.SourceEventID != event.SourceEventID || retry.Process.Key != event.Process.Key || retry.Process.ParentKey != event.Process.ParentKey {
				t.Fatal("local observation time changed source or process identity")
			}
			for index, process := range append([]model.Process{retry.Process}, retry.Ancestors...) {
				if !process.FirstSeen.Equal(retryTime) || !process.LastSeen.Equal(retryTime) {
					t.Fatalf("retry observation times were not refreshed: %+v", process)
				}
				if index > 0 && process.Key != event.Ancestors[index-1].Key {
					t.Fatal("local observation time changed ancestor identity")
				}
			}
		})
	}
}

func TestNormalizeTetragonDelayedExitPreservesSourceLifecycle(t *testing.T) {
	base := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	parent := tetragonProcess{ExecID: "parent:41", PID: 41, Binary: "/usr/bin/bash", StartTime: base.Add(-time.Minute)}
	childRaw, err := json.Marshal(tetragonEnvelope{Time: base.Add(2 * time.Second), ProcessExec: &tetragonProcessExec{
		Process: tetragonProcess{ExecID: "child:42", PID: 42, Binary: "/usr/bin/id"}, Parent: &parent,
	}})
	if err != nil {
		t.Fatal(err)
	}
	child, err := NormalizeTetragonJSON(childRaw, base.Add(3*time.Second), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	exited := base.Add(time.Second)
	raw, err := json.Marshal(tetragonEnvelope{Time: base.Add(2 * time.Second), ProcessExit: &tetragonProcessExit{Process: parent, Time: exited}})
	if err != nil {
		t.Fatal(err)
	}
	ingested := base.Add(4 * time.Second)
	event, err := NormalizeTetragonJSON(raw, ingested, Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if !event.EventTime.Equal(exited) || event.Process.ExitedAt == nil || !event.Process.ExitedAt.Equal(exited) || !event.Process.StartTime.Equal(parent.StartTime) {
		t.Fatalf("delayed source exit lifecycle was changed: %+v", event)
	}
	if !event.Process.FirstSeen.Equal(ingested) || !event.Process.LastSeen.Equal(ingested) || !event.Process.FirstSeen.After(child.Ancestors[0].FirstSeen) {
		t.Fatalf("delayed exit observations did not follow ingestion: %+v", event.Process)
	}
	if event.Process.Key != child.Ancestors[0].Key || event.SourceEventID != "exit:parent:41:"+exited.Format(time.RFC3339Nano) || !bytes.Equal(event.RawJSON, raw) {
		t.Fatal("delayed exit source identity or raw payload changed")
	}
	retry, err := NormalizeTetragonJSON(raw, ingested.Add(time.Minute), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if retry.ID != event.ID || retry.SourceEventID != event.SourceEventID || retry.Process.Key != event.Process.Key || !retry.EventTime.Equal(exited) || !retry.Process.ExitedAt.Equal(exited) {
		t.Fatal("retry changed delayed exit lifecycle or identity")
	}
}

func TestNormalizeTetragonZeroIngestRetainsSourceFallback(t *testing.T) {
	sourceTime := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		eventAt time.Time
		startAt time.Time
		want    time.Time
	}{
		{name: "event", eventAt: sourceTime, startAt: sourceTime.Add(-time.Second), want: sourceTime},
		{name: "start", startAt: sourceTime, want: sourceTime},
		{name: "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(tetragonEnvelope{Time: test.eventAt, ProcessExec: &tetragonProcessExec{
				Process: tetragonProcess{ExecID: "source:42", PID: 42, Binary: "/usr/bin/id", StartTime: test.startAt},
				Parent:  &tetragonProcess{ExecID: "parent:41", PID: 41, Binary: "/usr/bin/bash"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			event, err := NormalizeTetragonJSON(raw, time.Time{}, Metadata{BootID: "boot"})
			if err != nil {
				t.Fatal(err)
			}
			if !event.IngestTime.IsZero() || !event.EventTime.Equal(test.want) || !event.Process.StartTime.Equal(test.startAt) {
				t.Fatalf("missing ingest invented a lifecycle or ingest date: %+v", event)
			}
			for _, process := range append([]model.Process{event.Process}, event.Ancestors...) {
				if !process.FirstSeen.Equal(test.want) || !process.LastSeen.Equal(test.want) {
					t.Fatalf("zero-ingest observation fallback changed: %+v", process)
				}
			}
		})
	}
}

func TestTetragonUsesEffectiveUIDForRootShell(t *testing.T) {
	raw := []byte(`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:1","pid":42,"uid":0,"binary":"/usr/bin/bash"},"parent":{"exec_id":"parent:1","pid":41}}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if event.Process.EUID != 0 || event.Process.UID != model.UnknownCredentialID {
		t.Fatalf("top-level uid was not treated as effective UID: %+v", event.Process)
	}
}

func TestTetragonProcessCredentialsPreserveRealAndEffectiveIDs(t *testing.T) {
	raw := []byte(`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:1","pid":42,"uid":0,"binary":"/usr/bin/bash","process_credentials":{"uid":1000,"euid":0,"gid":1001,"egid":0}},"parent":{"exec_id":"parent:1","pid":41}}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	process := event.Process
	if process.UID != 1000 || process.EUID != 0 || process.GID != 1001 || process.EGID != 0 {
		t.Fatalf("credentials lost distinction between real and effective IDs: %+v", process)
	}
}

func TestTetragonMissingUIDIsUnknown(t *testing.T) {
	raw := []byte(`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:1","pid":42,"binary":"/usr/bin/bash","process_credentials":{}}}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if event.Process.EUID != model.UnknownCredentialID || event.Process.UID != model.UnknownCredentialID || event.Completeness != model.CompletenessPartial {
		t.Fatalf("missing credential was treated as UID 0: %+v", event)
	}
}

func TestTetragonParentExecIDRetainedWithoutParentObject(t *testing.T) {
	raw := []byte(`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:1","parent_exec_id":"parent:1","pid":42,"uid":1000,"binary":"/usr/bin/bash"}}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if event.Process.ParentKey == "" || event.Process.LineageConfidence != model.LineageVerified || event.Process.PPID != -1 || event.Process.Complete {
		t.Fatalf("explicit parent identity was not retained truthfully: %+v", event.Process)
	}
}

func TestTetragonRetainsBoundedAncestorSnapshotsWithoutArguments(t *testing.T) {
	source := tetragonProcess{ExecID: "child:1", ParentExecID: "parent:1", PID: 42, Binary: "/usr/bin/bash"}
	parent := tetragonProcess{ExecID: "parent:1", ParentExecID: "ancestor:1", PID: 41, Binary: "/usr/sbin/php-fpm", Arguments: "--token private-value"}
	ancestors := []tetragonProcess{parent}
	for index := 0; index < maxTetragonAncestors+10; index++ {
		ancestors = append(ancestors, tetragonProcess{ExecID: fmt.Sprintf("ancestor:%d", index+1), PID: index + 100, Binary: "/usr/bin/worker", Arguments: "--password private-value"})
	}
	raw, err := json.Marshal(tetragonEnvelope{Time: time.Now(), ProcessExec: &tetragonProcessExec{Process: source, Parent: &parent, Ancestors: ancestors}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Ancestors) < 1 || len(event.Ancestors) > maxTetragonAncestors || event.Ancestors[0].Key != event.Process.ParentKey {
		t.Fatalf("ancestor snapshots were not retained in bounded parent order: %+v", event.Ancestors)
	}
	seen := make(map[string]bool)
	for _, context := range event.Ancestors {
		if seen[context.Key] {
			t.Fatalf("duplicate ancestor key: %s", context.Key)
		}
		seen[context.Key] = true
		if len(context.Argv) != 1 || context.Argv[0] != context.Exe {
			t.Fatalf("flattened ancestor argument data was retained: %+v", context)
		}
	}
	if event.Completeness != model.CompletenessPartial || len(event.TruncatedFields) == 0 {
		t.Fatal("ancestor truncation was not disclosed")
	}
}

func TestTetragonIncompleteParentDoesNotClaimVerifiedLineage(t *testing.T) {
	raw := []byte(`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:1","pid":42,"uid":1000,"binary":"/usr/bin/bash"},"parent":{"pid":41}}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if event.Process.LineageConfidence == model.LineageVerified || event.Process.ParentKey != "" || event.Process.Complete {
		t.Fatalf("incomplete parent was overclaimed: %+v", event.Process)
	}
}

func TestTetragonConflictingParentsDoNotUsePIDFallback(t *testing.T) {
	raw := []byte(`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:1","parent_exec_id":"parent:1","pid":42,"uid":1000,"binary":"/usr/bin/bash"},"parent":{"exec_id":"parent:2","pid":41}}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if event.Process.LineageConfidence == model.LineageVerified || event.Process.PPID != -1 || event.Process.Complete || event.Completeness != model.CompletenessPartial {
		t.Fatalf("contradictory parent was overclaimed: %+v", event)
	}
}

func TestTetragonMissingExecIDDoesNotCreateSharedSourceIdentity(t *testing.T) {
	raw := []byte(`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"pid":42,"uid":0,"binary":"/usr/bin/bash"}}}`)
	event, err := NormalizeTetragonJSON(raw, time.Now(), Metadata{BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if event.SourceEventID != "" || event.ID != "" {
		t.Fatalf("missing source identity would deduplicate unrelated executions: %+v", event)
	}
}

func TestNormalizeTetragonUnsupportedEvent(t *testing.T) {
	_, err := NormalizeTetragonJSON([]byte(`{"process_kprobe":{}}`), time.Now(), Metadata{})
	if !errors.Is(err, ErrUnsupportedEvent) {
		t.Fatalf("error = %v, want ErrUnsupportedEvent", err)
	}
}

func TestCommandSpecRejectsMissingPathAndNUL(t *testing.T) {
	if err := (CommandSpec{}).validate(); err == nil {
		t.Fatal("missing path accepted")
	}
	if err := (CommandSpec{Path: "/bin/echo", Args: []string{"bad\x00arg"}}).validate(); err == nil {
		t.Fatal("NUL argument accepted")
	}
}

func TestTetragonJSONRunsEventCommand(t *testing.T) {
	collector := NewTetragonJSON(CommandSpec{
		Path: os.Args[0],
		Args: []string{"-test.run=TestTetragonCommandHelper", "--", "literal;not-a-shell-command"},
		Env:  []string{"XE_ANTISHELL_TETRAGON_HELPER=1"},
	}, Metadata{HostID: "host", BootID: "boot"})
	var events []model.Event
	err := collector.Run(context.Background(), SinkFunc(func(_ context.Context, event model.Event) error {
		events = append(events, event)
		return nil
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(events) != 1 || events[0].Process.Exe != "/usr/bin/id" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestTetragonJSONDrainsLargeStderr(t *testing.T) {
	value := NewTetragonJSON(CommandSpec{
		Path: os.Args[0],
		Args: []string{"-test.run=TestTetragonCommandHelper", "--", "large-stderr"},
		Env:  []string{"XE_ANTISHELL_TETRAGON_HELPER=1"},
	}, Metadata{BootID: "boot"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := value.Run(ctx, SinkFunc(func(context.Context, model.Event) error { return nil })); err != nil {
		t.Fatal(err)
	}
}

func TestTetragonJSONSkipsOneMalformedRecord(t *testing.T) {
	value := NewTetragonJSON(CommandSpec{Path: "/unused"}, Metadata{BootID: "boot"})
	input := bytes.NewBufferString("{malformed}\n" +
		`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:2","pid":2,"uid":1000,"binary":"/usr/bin/id"}}}` + "\n")
	var events []model.Event
	err := value.consume(context.Background(), input, SinkFunc(func(_ context.Context, event model.Event) error {
		events = append(events, event)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || value.Health().ParseErrors != 1 {
		t.Fatalf("malformed record handling: events=%d health=%+v", len(events), value.Health())
	}
}

func TestTetragonCommandHelper(t *testing.T) {
	if os.Getenv("XE_ANTISHELL_TETRAGON_HELPER") != "1" {
		return
	}
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "literal;not-a-shell-command" {
		if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "large-stderr" {
			os.Exit(3)
		}
		fmt.Fprint(os.Stderr, strings.Repeat("x", maxTetragonStderrBytes*2))
	}
	fmt.Fprintln(os.Stdout, `{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"id:1","pid":1,"uid":0,"binary":"/usr/bin/id"}}}`)
	os.Exit(0)
}
