package collector

import (
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestAuditAssemblerHandlesInterleavedExecEvents(t *testing.T) {
	assembler := NewAuditAssembler(AuditAssemblerOptions{Metadata: Metadata{BootID: "boot"}})
	now := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	lines := []string{
		`type=SYSCALL msg=audit(1767225600.100:10): arch=c000003e syscall=59 success=yes exit=0 pid=100 ppid=10 auid=1000 uid=1000 euid=1000 gid=1000 egid=1000 exe="/usr/bin/bash"`,
		`type=SYSCALL msg=audit(1767225600.200:11): arch=c000003e syscall=59 success=yes exit=0 pid=101 ppid=10 auid=1000 uid=1000 euid=1000 gid=1000 egid=1000 exe="/usr/bin/id"`,
		`type=EXECVE msg=audit(1767225600.100:10): argc=3 a0="bash" a1="-c" a2="id"`,
		`type=EXECVE msg=audit(1767225600.200:11): argc=1 a0="id"`,
		`type=CWD msg=audit(1767225600.100:10): cwd="/var/www/html"`,
		`type=EOE msg=audit(1767225600.200:11):`,
		`type=EOE msg=audit(1767225600.100:10):`,
	}
	var events int
	for _, line := range lines {
		emitted, err := assembler.Feed(line, now)
		if err != nil {
			t.Fatalf("Feed(%q) error = %v", line, err)
		}
		for _, event := range emitted {
			events++
			if event.SourceEventID == "10" {
				if event.Process.CWD != "/var/www/html" || len(event.Process.Argv) != 3 || event.Process.Argv[2] != "id" {
					t.Fatalf("unexpected event 10: %+v", event)
				}
			}
		}
	}
	if events != 2 {
		t.Fatalf("got %d events, want 2", events)
	}
}

func TestAuditAssemblerFiltersByExecutableBasename(t *testing.T) {
	assembler := NewAuditAssembler(AuditAssemblerOptions{IncludeExecutables: []string{"bash"}})
	now := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	lines := []string{
		`type=SYSCALL msg=audit(1767225600.100:20): arch=c000003e syscall=59 success=yes exit=0 pid=200 ppid=10 uid=1000 euid=1000 gid=1000 egid=1000 exe="/usr/bin/bash"`,
		`type=EXECVE msg=audit(1767225600.100:20): argc=1 a0="bash"`,
		`type=EOE msg=audit(1767225600.100:20):`,
		`type=SYSCALL msg=audit(1767225600.200:21): arch=c000003e syscall=59 success=yes exit=0 pid=201 ppid=10 uid=1000 euid=1000 gid=1000 egid=1000 exe="/usr/bin/id"`,
		`type=EXECVE msg=audit(1767225600.200:21): argc=1 a0="id"`,
		`type=EOE msg=audit(1767225600.200:21):`,
	}
	var events []model.Event
	for _, line := range lines {
		produced, err := assembler.Feed(line, now)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, produced...)
	}
	if len(events) != 1 || events[0].Process.Exe != "/usr/bin/bash" {
		t.Fatalf("filtered events = %#v, want only bash", events)
	}
}

func TestAuditAssemblerEmptyExecutableFilterKeepsAllExecs(t *testing.T) {
	assembler := NewAuditAssembler(AuditAssemblerOptions{IncludeExecutables: []string{}})
	now := time.Now().UTC()
	lines := []string{
		`type=SYSCALL msg=audit(1767225600.100:22): pid=202 ppid=1 exe="/usr/bin/id"`,
		`type=EXECVE msg=audit(1767225600.100:22): argc=1 a0="id"`,
		`type=EOE msg=audit(1767225600.100:22):`,
	}
	var events []model.Event
	for _, line := range lines {
		produced, err := assembler.Feed(line, now)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, produced...)
	}
	if len(events) != 1 || events[0].Process.Exe != "/usr/bin/id" {
		t.Fatalf("empty filter changed legacy behavior: %#v", events)
	}
}

func TestAuditAssemblerFlushesIncompleteAndDecodesHexArgument(t *testing.T) {
	assembler := NewAuditAssembler(AuditAssemblerOptions{Timeout: time.Second})
	now := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	_, err := assembler.Feed(`type=EXECVE msg=audit(1767225600.100:12): argc=1 a0=2F7573722F62696E2F6964`, now)
	if err != nil {
		t.Fatalf("Feed() error = %v", err)
	}
	events := assembler.FlushExpired(now.Add(2 * time.Second))
	if len(events) != 1 || len(events[0].Process.Argv) != 1 || events[0].Process.Argv[0] != "/usr/bin/id" {
		t.Fatalf("unexpected events: %+v", events)
	}
	if events[0].Completeness == "complete" {
		t.Fatalf("incomplete event marked complete: %+v", events[0])
	}
}

func TestAuditAssemblerIgnoresNonExecGroup(t *testing.T) {
	assembler := NewAuditAssembler(AuditAssemblerOptions{})
	now := time.Now()
	lines := []string{
		`type=SYSCALL msg=audit(1767225600.100:13): arch=c000003e syscall=2 pid=100 ppid=10 exe="/usr/bin/cat"`,
		`type=EOE msg=audit(1767225600.100:13):`,
	}
	var events int
	for _, line := range lines {
		emitted, err := assembler.Feed(line, now)
		if err != nil {
			t.Fatal(err)
		}
		events += len(emitted)
	}
	if events != 0 {
		t.Fatalf("emitted %d non-exec events", events)
	}
}

func TestAuditAssemblerRejectsMalformedRecord(t *testing.T) {
	assembler := NewAuditAssembler(AuditAssemblerOptions{})
	if _, err := assembler.Feed("not an audit record", time.Now()); err == nil {
		t.Fatal("Feed() error = nil")
	}
}

func TestAuditAssemblerDoesNotHexDecodeQuotedNumericArgument(t *testing.T) {
	assembler := NewAuditAssembler(AuditAssemblerOptions{})
	now := time.Now().UTC()
	lines := []string{
		`type=SYSCALL msg=audit(1700000000.000:77): pid=300 ppid=1 uid=1000 euid=1000 gid=1000 egid=1000 exe="/bin/echo"`,
		`type=EXECVE msg=audit(1700000000.000:77): argc=2 a0="echo" a1="1234"`,
		`type=EOE msg=audit(1700000000.000:77):`,
	}
	var events []model.Event
	for _, line := range lines {
		produced, err := assembler.Feed(line, now)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, produced...)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if got := events[0].Process.Argv; len(got) != 2 || got[1] != "1234" {
		t.Fatalf("quoted numeric argument changed: %#v", got)
	}
}
