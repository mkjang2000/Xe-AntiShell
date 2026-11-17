package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestColdOperationContextKeepsDurableExitAndNewerPIDOwner(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 0, 0, 10, 0, time.UTC)
	event := operationFixture(t, "file.write", now)
	closed := event.Process
	exitAt := event.EventTime.Add(2 * time.Second)
	closed.ExitedAt = &exitAt
	closed.FirstSeen, closed.LastSeen = event.EventTime, exitAt
	closed.EUID, closed.UID, closed.CWD = 1000, 1000, "/srv/previous"
	if err := store.SaveProcess(ctx, event.BootID, closed); err != nil {
		t.Fatal(err)
	}
	// A successful live restart snapshot omits the closed identity. The same
	// numeric PID can already belong to another execution in the live graph.
	newer := model.Process{Key: "newer-owner", ExecID: "newer-owner", PID: closed.PID, StartTime: now.Add(-time.Second), FirstSeen: now, LastSeen: now, Exe: "/usr/bin/sleep", OriginService: "maintenance.service"}
	service.lineage.Restore([]model.Process{newer})
	event.Process.EUID, event.Process.UID, event.Process.CWD = 0, 0, "/tmp/current"
	for attempt := 0; attempt < 2; attempt++ {
		copy := event
		copy.Ancestors = append([]model.Process(nil), event.Ancestors...)
		copy.IngestTime = now.Add(time.Duration(attempt) * time.Second)
		if err := service.processEvent(ctx, &copy); err != nil {
			t.Fatalf("cold-context operation attempt %d failed: %v", attempt, err)
		}
	}
	process, err := store.GetProcess(ctx, closed.Key)
	if err != nil || process.ExitedAt == nil || !process.ExitedAt.Equal(exitAt) {
		t.Fatalf("delayed operation reopened a durable closed identity: %#v %v", process, err)
	}
	if process.LastSeen.Before(process.FirstSeen) {
		t.Fatal("cold context broke the observation time invariant")
	}
	current, ok := service.lineage.CurrentByPID(closed.PID)
	if !ok || current.Key != newer.Key {
		t.Fatalf("delayed old operation replaced the newer PID owner: %#v", current)
	}
	stored, err := store.GetEvent(ctx, event.ID)
	if err != nil || stored.Process.ExitedAt != nil || stored.Process.EUID != 0 || stored.Process.UID != 0 || stored.Process.CWD != "/tmp/current" {
		t.Fatalf("source observation was replaced by a lifecycle summary: %#v %v", stored.Process, err)
	}
}

func TestOperationKeepsSourceCredentialsAndAncestorSnapshot(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	ctx := context.Background()
	event := operationFixture(t, "file.write", time.Date(2026, 11, 17, 0, 0, 10, 0, time.UTC))
	known := event.Process
	known.EUID, known.UID, known.CWD = 1000, 1000, "/srv/previous"
	ancestor := event.Ancestors[0]
	ancestor.EUID, ancestor.UID, ancestor.CWD = 1000, 1000, "/srv/parent-previous"
	service.lineage.Restore([]model.Process{ancestor, known})
	event.Process.EUID, event.Process.UID, event.Process.CWD = 0, 0, "/tmp/current"
	event.Ancestors[0].EUID, event.Ancestors[0].UID, event.Ancestors[0].CWD = 0, 0, "/tmp/parent-current"
	if err := service.processEvent(ctx, &event); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetEvent(ctx, event.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Process.EUID != 0 || stored.Process.UID != 0 || stored.Process.CWD != "/tmp/current" {
		t.Fatalf("known context replaced operation source credentials: %#v", stored.Process)
	}
	if len(stored.Ancestors) != 1 || stored.Ancestors[0].EUID != 0 || stored.Ancestors[0].UID != 0 || stored.Ancestors[0].CWD != "/tmp/parent-current" {
		t.Fatalf("known context replaced source ancestor metadata: %#v", stored.Ancestors)
	}
}

func TestOperationRetryRejectsChangedSourceParentIdentity(t *testing.T) {
	_, store, _ := newTestDependencies(t, config.CollectorDisabled, nil)
	defer store.Close()
	ctx := context.Background()
	event := operationFixture(t, "file.write", time.Date(2026, 11, 17, 0, 0, 10, 0, time.UTC))
	if err := store.SaveEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*model.Event){
		func(event *model.Event) { event.Process.ParentKey = "different-source-parent" },
		func(event *model.Event) { event.Process.PPID++ },
		func(event *model.Event) {
			event.Ancestors = append([]model.Process(nil), event.Ancestors...)
			event.Ancestors[0].ParentKey = "different-ancestor-parent"
		},
	} {
		copy := event
		change(&copy)
		if err := store.SaveEvent(ctx, copy); !errors.Is(err, storage.ErrConflict) {
			t.Fatalf("changed source parent was treated as harmless context enrichment: %v", err)
		}
	}
}

func TestSubmitSnapshotsTypedObservationPayloads(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	service.accepting = true
	for _, kind := range []string{"process.exec_observation", "file.write", "network.connect"} {
		event := operationFixture(t, kind, time.Now().UTC())
		if err := service.Submit(context.Background(), event); err != nil {
			t.Fatal(err)
		}
		switch kind {
		case "process.exec_observation":
			event.Execution.Option = "changed"
		case "file.write":
			event.File.Path = "/changed"
			*event.File.ReturnValue = -999
		case "network.connect":
			event.Network.DestinationAddress = "changed"
			*event.Network.ReturnValue = -999
		}
		queued := <-service.eventQueue
		if (queued.Execution != nil && queued.Execution.Option == "changed") ||
			(queued.File != nil && (queued.File.Path == "/changed" || *queued.File.ReturnValue == -999)) ||
			(queued.Network != nil && (queued.Network.DestinationAddress == "changed" || *queued.Network.ReturnValue == -999)) {
			t.Fatal("caller mutation changed queued evidence")
		}
	}
}
