package hostmetrics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (s *Sampler) processes(ctx context.Context, next *counters, compatible bool, seconds float64, problems *[]string) ([]Process, int) {
	result := []Process{}
	entries, err := os.ReadDir(s.proc)
	if err != nil {
		*problems = append(*problems, "process inventory unavailable")
		return result, 0
	}
	count := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			*problems = append(*problems, "process sampling cancelled")
			break
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 || !entry.IsDir() {
			continue
		}
		count++
		if count > 32768 {
			continue
		}
		root := filepath.Join(s.proc, entry.Name())
		body, err := os.ReadFile(filepath.Join(root, "stat"))
		if err != nil {
			continue
		}
		line := string(body)
		open, close := strings.Index(line, "("), strings.LastIndex(line, ") ")
		if open < 0 || close < open {
			continue
		}
		f := strings.Fields(line[close+2:])
		if len(f) < 22 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		start := number(f[19])
		ticks := number(f[11]) + number(f[12])
		key := fmt.Sprintf("%d:%d", pid, start)
		next.processes[key] = ticks
		process := Process{PID: pid, PPID: ppid, Name: line[open+1 : close], StartTicks: start, UID: -1, RSSBytes: number(f[21]) * uint64(os.Getpagesize())}
		process.Exe, _ = os.Readlink(filepath.Join(root, "exe"))
		for _, status := range strings.Split(readText(filepath.Join(root, "status")), "\n") {
			if strings.HasPrefix(status, "Uid:") {
				v := strings.Fields(status)
				if len(v) > 1 {
					process.UID, _ = strconv.ParseInt(v[1], 10, 64)
				}
				break
			}
		}
		for _, cgroup := range strings.Split(readText(filepath.Join(root, "cgroup")), "\n") {
			parts := strings.Split(cgroup, "/")
			for i := len(parts) - 1; i >= 0; i-- {
				if strings.HasSuffix(parts[i], ".service") || strings.HasSuffix(parts[i], ".scope") {
					process.OriginService = parts[i]
					break
				}
			}
			if process.OriginService != "" {
				break
			}
		}
		if previous, ok := s.previous.processes[key]; compatible && ok {
			process.CPUPercent = rate(ticks, previous, seconds)
		}
		result = append(result, process)
	}
	return result, count
}
