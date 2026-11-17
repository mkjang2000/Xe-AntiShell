// Package procfs reads the minimum live-process metadata needed to seed the
// agent's boot-scoped process lineage. It deliberately does not read process
// environments or command lines.
package procfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

// Linux exposes /proc/PID/stat starttime in USER_HZ clock ticks. USER_HZ is
// fixed at 100 for the Linux procfs userspace ABI on the supported platforms.
const userClockTicksPerSecond int64 = 100

// Snapshotter reads one procfs mount. Root is injectable so parsing and
// process-exit races can be tested without consulting the host process table.
type Snapshotter struct {
	root string
	now  func() time.Time
}

// OriginService returns the leaf-most systemd service or container scope that
// owns pid. It is intentionally a separate best-effort lookup so a short-lived
// exec event can be enriched even when the startup snapshot missed its parent.
func (s *Snapshotter) OriginService(ctx context.Context, pid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s == nil || s.root == "" || !filepath.IsAbs(s.root) {
		return "", errors.New("procfs origin lookup requires an absolute root")
	}
	if pid < 1 {
		return "", errors.New("procfs origin lookup requires a positive PID")
	}
	body, err := os.ReadFile(filepath.Join(s.root, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		components := strings.Split(filepath.Clean(parts[2]), string(filepath.Separator))
		for index := len(components) - 1; index >= 0; index-- {
			component := components[index]
			if strings.HasSuffix(component, ".service") || isContainerScope(component) {
				return component, nil
			}
		}
	}
	return "", errors.New("process has no systemd service or container scope")
}

func isContainerScope(value string) bool {
	if !strings.HasSuffix(value, ".scope") {
		return false
	}
	return strings.HasPrefix(value, "docker-") ||
		strings.HasPrefix(value, "libpod-") ||
		strings.HasPrefix(value, "cri-containerd-")
}

func New(root string) *Snapshotter {
	return &Snapshotter{root: filepath.Clean(root), now: time.Now}
}

// Snapshot returns a self-consistent best-effort view of the processes that
// remained readable during the scan. A process that exits or becomes
// unreadable is skipped; failure to read the procfs root or boot time is
// returned because no trustworthy snapshot can then be constructed.
func (s *Snapshotter) Snapshot(ctx context.Context, bootID string) ([]model.Process, error) {
	if strings.TrimSpace(bootID) == "" {
		return nil, errors.New("procfs snapshot requires a boot ID")
	}
	if s == nil || s.root == "" || !filepath.IsAbs(s.root) {
		return nil, errors.New("procfs snapshot requires an absolute root")
	}
	bootTime, err := readBootTime(filepath.Join(s.root, "stat"))
	if err != nil {
		return nil, fmt.Errorf("read procfs boot time: %w", err)
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("read procfs root: %w", err)
	}
	now := s.now().UTC()
	byPID := make(map[int]model.Process)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 || strconv.Itoa(pid) != entry.Name() {
			continue
		}
		process, err := s.readProcess(ctx, pid, bootID, bootTime, now)
		if err != nil {
			// Process lifecycle and procfs permission races are expected. An
			// incomplete record must not be represented as verified lineage.
			continue
		}
		byPID[pid] = process
	}

	processes := make([]model.Process, 0, len(byPID))
	for pid, process := range byPID {
		if process.PPID > 0 {
			if parent, ok := byPID[process.PPID]; ok && !parent.StartTime.After(process.StartTime) {
				process.ParentKey = parent.Key
				process.Complete = true
				process.LineageConfidence = model.LineageInferred
			}
		}
		if pid == 1 || process.PPID == 0 {
			process.Complete = true
		}
		byPID[pid] = process
		processes = append(processes, process)
	}
	return processes, nil
}

func (s *Snapshotter) readProcess(ctx context.Context, pid int, bootID string, bootTime, observedAt time.Time) (model.Process, error) {
	dir := filepath.Join(s.root, strconv.Itoa(pid))
	statBody, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return model.Process{}, err
	}
	parsedPID, ppid, startTicks, err := parseProcessStat(string(statBody))
	if err != nil || parsedPID != pid {
		return model.Process{}, errors.New("invalid process stat")
	}
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil || !filepath.IsAbs(exe) {
		return model.Process{}, errors.New("process executable is unavailable")
	}
	startTime := bootTime.Add(ticksToDuration(startTicks)).UTC()
	process := model.Process{
		PID:               pid,
		PPID:              ppid,
		StartTime:         startTime,
		Exe:               exe,
		UID:               model.UnknownCredentialID,
		EUID:              model.UnknownCredentialID,
		GID:               model.UnknownCredentialID,
		EGID:              model.UnknownCredentialID,
		LineageConfidence: model.LineageUnknown,
		FirstSeen:         observedAt,
		LastSeen:          observedAt,
	}
	process.Key = identity.ProcessKey(bootID, process, startTime)
	if origin, err := s.OriginService(ctx, pid); err == nil {
		process.OriginService = origin
	}
	if credentials, err := readCredentials(filepath.Join(dir, "status")); err == nil {
		process.UID = credentials.uid
		process.EUID = credentials.euid
		process.GID = credentials.gid
		process.EGID = credentials.egid
	}
	return process, nil
}

func readBootTime(path string) (time.Time, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "btime" {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || seconds < 0 {
			return time.Time{}, errors.New("invalid btime value")
		}
		return time.Unix(seconds, 0).UTC(), nil
	}
	return time.Time{}, errors.New("btime is missing")
}

// parseProcessStat extracts fields 1 (pid), 4 (ppid), and 22 (starttime).
// The command field may itself contain spaces or closing parentheses, so the
// delimiter before the state field is located from the right.
func parseProcessStat(value string) (pid, ppid int, startTicks uint64, err error) {
	value = strings.TrimSpace(value)
	open := strings.IndexByte(value, '(')
	close := strings.LastIndex(value, ") ")
	if open < 1 || close <= open {
		return 0, 0, 0, errors.New("malformed stat command field")
	}
	pid, err = strconv.Atoi(strings.TrimSpace(value[:open]))
	if err != nil || pid < 1 {
		return 0, 0, 0, errors.New("invalid stat pid")
	}
	fields := strings.Fields(value[close+2:])
	if len(fields) <= 19 {
		return 0, 0, 0, errors.New("stat has too few fields")
	}
	ppid, err = strconv.Atoi(fields[1])
	if err != nil || ppid < 0 {
		return 0, 0, 0, errors.New("invalid stat ppid")
	}
	startTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, 0, 0, errors.New("invalid stat starttime")
	}
	return pid, ppid, startTicks, nil
}

func ticksToDuration(ticks uint64) time.Duration {
	seconds := ticks / uint64(userClockTicksPerSecond)
	remainder := ticks % uint64(userClockTicksPerSecond)
	return time.Duration(seconds)*time.Second +
		time.Duration(remainder)*(time.Second/time.Duration(userClockTicksPerSecond))
}

type credentials struct {
	uid  int64
	euid int64
	gid  int64
	egid int64
}

func readCredentials(path string) (credentials, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return credentials{}, err
	}
	result := credentials{
		uid:  model.UnknownCredentialID,
		euid: model.UnknownCredentialID,
		gid:  model.UnknownCredentialID,
		egid: model.UnknownCredentialID,
	}
	uidFound, gidFound := false, false
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "Uid":
			result.uid, result.euid, err = parseCredentialPair(fields[1], fields[2])
			uidFound = err == nil
		case "Gid":
			result.gid, result.egid, err = parseCredentialPair(fields[1], fields[2])
			gidFound = err == nil
		}
		if err != nil {
			return credentials{}, err
		}
	}
	if !uidFound || !gidFound {
		return credentials{}, errors.New("status credentials are missing")
	}
	return result, nil
}

func parseCredentialPair(realValue, effectiveValue string) (int64, int64, error) {
	realID, err := strconv.ParseInt(realValue, 10, 64)
	if err != nil || realID < 0 {
		return 0, 0, errors.New("invalid real credential")
	}
	effectiveID, err := strconv.ParseInt(effectiveValue, 10, 64)
	if err != nil || effectiveID < 0 {
		return 0, 0, errors.New("invalid effective credential")
	}
	return realID, effectiveID, nil
}
