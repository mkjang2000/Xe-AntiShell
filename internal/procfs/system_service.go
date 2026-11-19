package procfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

var errSystemService = errors.New("direct system service membership is unverified")

// SystemService ties the live unified cgroup to the observed process and boot.
// A unit basename from a delegated subtree, user manager or container is not
// a host system service identity.
func (s *Snapshotter) SystemService(ctx context.Context, event model.Event) (string, error) {
	p := event.Process
	if s == nil || !filepath.IsAbs(s.root) || p.PID < 1 || !filepath.IsAbs(p.Exe) || event.EventTime.IsZero() || event.BootID == "" {
		return "", errSystemService
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	boot, err := os.ReadFile(filepath.Join(s.root, "sys/kernel/random/boot_id"))
	if err != nil || strings.TrimSpace(string(boot)) != event.BootID {
		return "", errSystemService
	}
	dir := filepath.Join(s.root, strconv.Itoa(p.PID))
	readStart := func() (uint64, error) {
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			return 0, errSystemService
		}
		pid, _, ticks, err := parseProcessStat(string(stat))
		if err != nil || pid != p.PID {
			return 0, errSystemService
		}
		return ticks, nil
	}
	ticks, err := readStart()
	if err != nil {
		return "", err
	}
	// uptime is rounded down to centiseconds; stat starttime is rounded down
	// to USER_HZ ticks. Use an upper bound on creation to exclude a recycled
	// PID without equating an exec timestamp to the process's fork timestamp.
	uptime, err := os.ReadFile(filepath.Join(s.root, "uptime"))
	if err != nil {
		return "", errSystemService
	}
	seconds, _, _ := strings.Cut(string(uptime), " ")
	elapsed, err := time.ParseDuration(seconds + "s")
	if err != nil || elapsed < 0 || ticksToDuration(ticks) > elapsed {
		return "", errSystemService
	}
	latestStart := s.now().Add(-elapsed + ticksToDuration(ticks) + ticksToDuration(1))
	if event.EventTime.Before(latestStart) {
		return "", errSystemService
	}
	body, err := os.ReadFile(filepath.Join(dir, "cgroup"))
	if err != nil {
		return "", errSystemService
	}
	service := systemServiceUnit(string(body))
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if service == "" || err != nil || exe != p.Exe {
		return "", errSystemService
	}
	if after, err := readStart(); err != nil || after != ticks {
		return "", errSystemService
	}
	return service, nil
}

func systemServiceUnit(cgroups string) string {
	var service string
	for _, line := range strings.Split(cgroups, "\n") {
		path, unified := strings.CutPrefix(line, "0::")
		if !unified {
			continue
		}
		parts := strings.Split(path, "/")
		if service != "" || len(parts) < 3 || parts[0] != "" || parts[1] != "system.slice" {
			return ""
		}
		for _, slice := range parts[2 : len(parts)-1] {
			if !strings.HasSuffix(slice, ".slice") {
				return ""
			}
		}
		service = parts[len(parts)-1]
		if !managed.ValidApplicationService(service) {
			return ""
		}
	}
	return service
}
