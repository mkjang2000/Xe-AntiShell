package detection

import (
	"testing"
	"time"

	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

func TestWebDescendantShellFinding(t *testing.T) {
	now := time.Now().UTC()
	graph := lineage.New()
	parentEvent := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 100, PPID: 1, ExecID: "web", Exe: "/usr/sbin/php-fpm"},
	}
	graph.Observe(&parentEvent)
	childEvent := model.Event{
		ID: "event-1", Type: "process.exec", BootID: "boot",
		EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second),
		Process: model.Process{PID: 101, PPID: 100, ExecID: "shell", Exe: "/bin/bash", EUID: 0},
	}
	graph.Observe(&childEvent)

	findings := New([]string{"php-fpm"}, []string{"sh", "bash"}).Evaluate(childEvent, graph)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != "critical" || findings[0].RuleID != "web-descendant-root-shell" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	retry := New([]string{"php-fpm"}, []string{"sh", "bash"}).Evaluate(childEvent, graph)
	if len(retry) != 1 || retry[0].ID != findings[0].ID {
		t.Fatalf("finding ID is not idempotent: first=%+v retry=%+v", findings, retry)
	}
}

func TestSSHDescendantShellDoesNotAlert(t *testing.T) {
	now := time.Now().UTC()
	graph := lineage.New()
	parent := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 200, PPID: 1, Exe: "/usr/sbin/sshd"}}
	graph.Observe(&parent)
	child := model.Event{ID: "event-2", Type: "process.exec", BootID: "boot", EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second), Process: model.Process{PID: 201, PPID: 200, Exe: "/bin/bash", EUID: 1000}}
	graph.Observe(&child)
	if findings := New([]string{"php-fpm", "nginx"}, []string{"bash"}).Evaluate(child, graph); len(findings) != 0 {
		t.Fatalf("normal SSH shell caused findings: %+v", findings)
	}
}

func TestAllowedWebShellPairDoesNotAlert(t *testing.T) {
	now := time.Now().UTC()
	graph := lineage.New()
	parent := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 300, PPID: 1, Exe: "/usr/sbin/nginx"}}
	graph.Observe(&parent)
	child := model.Event{ID: "event-3", Type: "process.exec", BootID: "boot", EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second), Process: model.Process{PID: 301, PPID: 300, Exe: "/bin/sh", EUID: 1000}}
	graph.Observe(&child)
	engine := New([]string{"nginx"}, []string{"sh"}, []string{"nginx:sh"})
	if findings := engine.Evaluate(child, graph); len(findings) != 0 {
		t.Fatalf("allowed pair caused findings: %+v", findings)
	}
}

func TestWebServiceDescendantShellFinding(t *testing.T) {
	now := time.Now().UTC()
	graph := lineage.New()
	parent := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{
			PID: 400, PPID: 1, Exe: "/opt/node/bin/node",
			OriginService: "Orders-API.Service",
		},
	}
	graph.Observe(&parent)
	child := model.Event{
		ID: "event-4", Type: "process.exec", BootID: "boot",
		EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second),
		Process: model.Process{PID: 401, PPID: 400, Exe: "/bin/sh", EUID: 1000},
	}
	graph.Observe(&child)

	engine := NewWithServices(nil, []string{"orders-api.service"}, []string{"sh"})
	findings := engine.Evaluate(child, graph)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Summary != "shell sh descended from web process orders-api.service" {
		t.Fatalf("unexpected service finding: %+v", findings[0])
	}
}

func TestDirectOriginServiceFindingAndAllowedPair(t *testing.T) {
	now := time.Now().UTC()
	graph := lineage.New()
	event := model.Event{
		ID: "event-5", Type: "process.exec", BootID: "boot",
		EventTime: now, IngestTime: now,
		Process: model.Process{
			PID: 500, PPID: 1, Exe: "/bin/bash", EUID: 1000,
			OriginService: "civicnote.service",
		},
	}
	graph.Observe(&event)

	engine := NewWithServices(
		nil,
		[]string{"civicnote.service"},
		[]string{"bash"},
		[]string{"civicnote.service:bash"},
	)
	if findings := engine.Evaluate(event, graph); len(findings) != 0 {
		t.Fatalf("allowed service/shell pair caused findings: %+v", findings)
	}
}

func TestGenericRuntimeDoesNotMatchUnlistedService(t *testing.T) {
	now := time.Now().UTC()
	graph := lineage.New()
	parent := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{
			PID: 600, PPID: 1, Exe: "/usr/bin/node",
			OriginService: "vscode.service",
		},
	}
	graph.Observe(&parent)
	child := model.Event{
		ID: "event-6", Type: "process.exec", BootID: "boot",
		EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second),
		Process: model.Process{PID: 601, PPID: 600, Exe: "/bin/sh", EUID: 1000},
	}
	graph.Observe(&child)

	engine := NewWithServices(nil, []string{"orders-api.service"}, []string{"sh"})
	if findings := engine.Evaluate(child, graph); len(findings) != 0 {
		t.Fatalf("unlisted generic runtime caused findings: %+v", findings)
	}
}

func TestMatchWebOriginBeforeChildObservationUsesCurrentParent(t *testing.T) {
	now := time.Now().UTC()
	graph := lineage.New()
	parent := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 700, PPID: 1, Exe: "/usr/sbin/nginx"},
	}
	graph.Observe(&parent)
	child := model.Event{
		ID: "event-7", Type: "process.exec", BootID: "boot",
		EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second),
		Process: model.Process{PID: 701, PPID: 700, Exe: "/bin/sh", EUID: 1000},
	}

	engine := New([]string{"nginx"}, []string{"sh"})
	origin, matched := engine.MatchWebOrigin(child, graph)
	if !matched || origin != "nginx" {
		t.Fatalf("pre-observation origin = %q, matched=%t", origin, matched)
	}
	if _, exists := graph.CurrentByPID(child.Process.PID); exists {
		t.Fatal("origin preview unexpectedly retained child process")
	}
}

func TestMatchWebOriginDoesNotTreatShellItselfAsWebExecutable(t *testing.T) {
	graph := lineage.New()
	event := model.Event{
		Type:    "process.exec",
		Process: model.Process{PID: 800, PPID: 1, Exe: "/bin/sh"},
	}
	engine := New([]string{"sh"}, []string{"sh"})
	if origin, matched := engine.MatchWebOrigin(event, graph); matched {
		t.Fatalf("shell matched itself as web origin %q", origin)
	}
}

func TestMatchWebOriginDoesNotReplaceExplicitParentWithReusedPID(t *testing.T) {
	graph := lineage.New()
	now := time.Now().UTC()
	parent := model.Event{
		BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 900, PPID: 1, ExecID: "new-web", Exe: "/usr/sbin/nginx"},
	}
	graph.Observe(&parent)
	child := model.Event{
		Type: "process.exec", BootID: "boot", EventTime: now, IngestTime: now,
		Process: model.Process{PID: 901, PPID: 900, ParentKey: "proc-old-parent", Exe: "/bin/sh"},
	}
	engine := New([]string{"nginx"}, []string{"sh"})
	if origin, matched := engine.MatchWebOrigin(child, graph); matched {
		t.Fatalf("explicit absent parent was replaced by current PID owner %q", origin)
	}
}
