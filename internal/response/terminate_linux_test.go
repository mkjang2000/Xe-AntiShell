//go:build linux

package response

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"xe-antishell/internal/model"
	"xe-antishell/internal/procfs"
)

func ownSleep(t *testing.T) (*exec.Cmd, model.Event) {
	t.Helper()
	if Capability(true).State != model.CapabilitySupported {
		t.Skip("pidfd_open unavailable")
	}
	command := exec.Command("/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	bootID := strings.TrimSpace(string(boot))
	processes, err := procfs.New("/proc").Snapshot(context.Background(), bootID)
	if err != nil {
		t.Fatal(err)
	}
	for _, process := range processes {
		if process.PID == command.Process.Pid {
			return command, model.Event{Type: "process.exec", BootID: bootID, EventTime: time.Now().UTC(), Process: process}
		}
	}
	t.Fatal("owned test process unavailable")
	return nil, model.Event{}
}

func TestTerminateOnlyOwnedVerifiedProcess(t *testing.T) {
	command, event := ownSleep(t)
	if err := Terminate(context.Background(), event, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("owned process exited without SIGTERM")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owned test process remained alive after SIGTERM")
	}
}

func TestTerminateRefusesUncertainIdentityWithoutSignaling(t *testing.T) {
	command, original := ownSleep(t)
	for name, mutate := range map[string]func(*model.Event){
		"wrong boot":          func(e *model.Event) { e.BootID = "wrong-boot" },
		"stale event":         func(e *model.Event) { e.EventTime = time.Now().Add(-time.Minute) },
		"future event":        func(e *model.Event) { e.EventTime = time.Now().Add(time.Minute) },
		"start precision":     func(e *model.Event) { e.Process.StartTime = e.Process.StartTime.Add(time.Nanosecond) },
		"changed executable":  func(e *model.Event) { e.Process.Exe = "/bin/not-the-test-process" },
		"changed uid":         func(e *model.Event) { e.Process.UID++ },
		"changed service":     func(e *model.Event) { e.Process.OriginService += "wrong.service" },
		"unknown credentials": func(e *model.Event) { e.Process.EUID = -1 },
		"init":                func(e *model.Event) { e.Process.PID = 1 },
		"self":                func(e *model.Event) { e.Process.PID = os.Getpid() },
		"ancestor":            func(e *model.Event) { e.Process.PID = os.Getppid() },
	} {
		t.Run(name, func(t *testing.T) {
			event := original
			mutate(&event)
			if err := Terminate(context.Background(), event, time.Now().UTC()); err == nil {
				t.Fatal("uncertain target accepted")
			}
		})
	}
	fd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		t.Fatal("owned target was terminated by a refused action")
	}
	defer unix.Close(fd)
	if ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 0); err != nil || ready != 0 {
		t.Fatal("owned target exited during refusal tests")
	}
}
