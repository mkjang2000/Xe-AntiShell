//go:build linux

// Package response provides an explicitly gated post-execution termination
// actuator. It never prevents exec and never falls back to numeric-PID kill.
package response

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"xe-antishell/internal/model"
	"xe-antishell/internal/procfs"
)

const CapabilityName = "response.terminate"
const MaxEventAge = 3 * time.Second

var probeOnce sync.Once
var probeSupported bool
var probeAt time.Time

// Capability probes pidfd_open on the agent itself without sending a signal.
// Signal permission and target identity remain per-action requirements.
func Capability(enabled bool) model.Capability {
	probeOnce.Do(func() {
		fd, err := unix.PidfdOpen(os.Getpid(), 0)
		if err == nil {
			probeSupported = true
			_ = unix.Close(fd)
		}
		probeAt = time.Now().UTC()
	})
	value := model.Capability{Name: CapabilityName, Provider: "pidfd", Implementation: "implemented", State: model.CapabilityUnsupported, RuntimeState: "inactive", Reason: "pidfd_open is unavailable; numeric PID signaling is disabled"}
	if probeSupported {
		value.State, value.Reason = model.CapabilitySupported, "pidfd_open verified without signaling"
		value.RuntimeState, value.RuntimeReason = "available", "host-local termination opt-in is disabled"
		if enabled {
			value.RuntimeState, value.RuntimeReason = "active", "host-local opt-in enabled; strict per-process identity checks still apply"
			at := probeAt
			value.VerifiedAt = &at
		}
	}
	return value
}

// Terminate validates a fresh observation against live procfs twice, pins the
// process with pidfd, and sends SIGTERM. Linux pidfds pin process identity, not
// an exec generation; a final concurrent exec remains a documented limitation.
func Terminate(ctx context.Context, event model.Event, now time.Time) error {
	return TerminateInService(ctx, event, now, "")
}

// TerminateInService additionally remeasures host system unit membership
// immediately before signaling when the authorization came from an application.
func TerminateInService(ctx context.Context, event model.Event, now time.Time, service string) error {
	if err := preconditions(event, now); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != event.BootID {
		return errors.New("response refused: boot identity does not match")
	}
	fd, err := unix.PidfdOpen(event.Process.PID, 0)
	if err != nil {
		return errors.New("response refused: process handle unavailable")
	}
	defer unix.Close(fd)
	for index := 0; index < 2; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := liveIdentity(ctx, event); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if ready, err := unix.Poll(poll, 0); err != nil || ready != 0 {
			return errors.New("response refused: pinned process already exited")
		}
	}
	if service != "" {
		current, err := procfs.New("/proc").SystemService(ctx, event)
		if err != nil || current != service || event.Process.OriginService != service {
			return errors.New("response refused: direct system service no longer matches the application policy")
		}
	}
	if err := preconditions(event, time.Now().UTC()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		return errors.New("response refused: pidfd SIGTERM failed")
	}
	return nil
}

func preconditions(event model.Event, now time.Time) error {
	process := event.Process
	if event.Type != "process.exec" || event.BootID == "" || process.PID <= 1 || process.PID == os.Getpid() {
		return errors.New("response refused: protected or invalid process")
	}
	if event.EventTime.IsZero() || now.Sub(event.EventTime) > MaxEventAge || event.EventTime.After(now.Add(time.Second)) {
		return errors.New("response refused: stale or future execution event")
	}
	if process.StartTime.IsZero() || process.UID < 0 || process.EUID < 0 || !filepath.IsAbs(process.Exe) || strings.HasSuffix(process.Exe, " (deleted)") {
		return errors.New("response refused: incomplete process identity")
	}
	return nil
}

func liveIdentity(ctx context.Context, event model.Event) error {
	processes, err := procfs.New("/proc").Snapshot(ctx, event.BootID)
	if err != nil {
		return errors.New("response refused: live identity unavailable")
	}
	byPID := make(map[int]model.Process, len(processes))
	for _, process := range processes {
		byPID[process.PID] = process
	}
	// Protect the daemon's entire current ancestor chain, including its service
	// manager. Missing ancestry is uncertainty and therefore refuses the action.
	pid := os.Getpid()
	seen := map[int]bool{}
	for depth := 0; pid > 1; depth++ {
		if depth >= 128 || seen[pid] {
			return errors.New("response refused: protected ancestry is uncertain")
		}
		seen[pid] = true
		if event.Process.PID == pid {
			return errors.New("response refused: target is an agent ancestor")
		}
		process, exists := byPID[pid]
		if !exists || process.PPID < 1 {
			return errors.New("response refused: protected ancestry is unavailable")
		}
		pid = process.PPID
	}
	live, exists := byPID[event.Process.PID]
	if !exists || live.ExitedAt != nil || live.UID < 0 || live.EUID < 0 {
		return errors.New("response refused: target process is unavailable")
	}
	expected := event.Process
	// Exact equality deliberately refuses nanosecond source timestamps that
	// cannot be proven equal to procfs btime + USER_HZ start ticks.
	if !live.StartTime.Equal(expected.StartTime) || live.Exe != expected.Exe || live.UID != expected.UID || live.EUID != expected.EUID || live.OriginService != expected.OriginService {
		return errors.New("response refused: process start, executable, credentials, or service changed")
	}
	return nil
}
