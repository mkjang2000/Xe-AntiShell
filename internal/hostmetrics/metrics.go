// Package hostmetrics samples bounded host counters without reading process
// arguments or environments. Rates are unknown until two compatible samples.
package hostmetrics

import (
	"context"
	"os"
	"sort"
	"sync"
	"time"
)

type Snapshot struct {
	SampledAt       time.Time    `json:"sampled_at"`
	IntervalSeconds float64      `json:"interval_seconds"`
	CPU             *CPU         `json:"cpu"`
	Memory          *Memory      `json:"memory"`
	Filesystems     []Filesystem `json:"filesystems"`
	Disks           []DiskIO     `json:"disks"`
	Network         []Interface  `json:"network"`
	Processes       []Process    `json:"processes"`
	ProcessCount    int          `json:"process_count"`
	Errors          []string     `json:"errors"`
}
type CPU struct {
	UsagePercent *float64 `json:"usage_percent"`
	Load1        float64  `json:"load1"`
	LogicalCPUs  int      `json:"logical_cpus"`
}
type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	SwapTotalBytes uint64 `json:"swap_total_bytes"`
	SwapUsedBytes  uint64 `json:"swap_used_bytes"`
}
type Filesystem struct {
	Mount          string `json:"mount"`
	Type           string `json:"type"`
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	TotalInodes    uint64 `json:"total_inodes"`
	FreeInodes     uint64 `json:"free_inodes"`
}
type DiskIO struct {
	Name                string   `json:"name"`
	ReadBytesPerSecond  *float64 `json:"read_bytes_per_second"`
	WriteBytesPerSecond *float64 `json:"write_bytes_per_second"`
	ReadIOPS            *float64 `json:"read_iops"`
	WriteIOPS           *float64 `json:"write_iops"`
	BusyPercent         *float64 `json:"busy_percent"`
}
type Interface struct {
	Name             string   `json:"name"`
	State            string   `json:"state"`
	RxBytes          uint64   `json:"rx_bytes"`
	TxBytes          uint64   `json:"tx_bytes"`
	RxBytesPerSecond *float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond *float64 `json:"tx_bytes_per_second"`
	RxErrors         uint64   `json:"rx_errors"`
	TxErrors         uint64   `json:"tx_errors"`
	RxDropped        uint64   `json:"rx_dropped"`
	TxDropped        uint64   `json:"tx_dropped"`
}
type Process struct {
	PID           int      `json:"pid"`
	PPID          int      `json:"ppid"`
	StartTicks    uint64   `json:"start_ticks"`
	Name          string   `json:"name"`
	Exe           string   `json:"exe"`
	UID           int64    `json:"uid"`
	RSSBytes      uint64   `json:"rss_bytes"`
	CPUPercent    *float64 `json:"cpu_percent"`
	OriginService string   `json:"origin_service,omitempty"`
}

type counters struct {
	at          time.Time
	boot        string
	total, idle uint64
	disks       map[string][]uint64
	network     map[string][]uint64
	processes   map[string]uint64
}
type Sampler struct {
	mu        sync.Mutex
	proc, sys string
	previous  counters
	cached    Snapshot
}

func New(proc, sys string) *Sampler { return &Sampler{proc: proc, sys: sys} }
func (s *Sampler) Sample(ctx context.Context, limit int) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 2000 {
		limit = 200
	}
	if time.Since(s.cached.SampledAt) < 5*time.Second {
		return trimSnapshot(s.cached, limit)
	}
	now := time.Now().UTC()
	out := Snapshot{SampledAt: now, Filesystems: []Filesystem{}, Disks: []DiskIO{}, Network: []Interface{}, Processes: []Process{}, Errors: []string{}}
	next := counters{at: now, boot: readText(s.proc + "/sys/kernel/random/boot_id"), disks: map[string][]uint64{}, network: map[string][]uint64{}, processes: map[string]uint64{}}
	seconds := now.Sub(s.previous.at).Seconds()
	compatible := !s.previous.at.IsZero() && next.boot != "" && next.boot == s.previous.boot && seconds > 0
	if compatible {
		out.IntervalSeconds = seconds
	}
	out.CPU = s.cpu(&next, compatible, seconds, &out.Errors)
	out.Memory = s.memory(&out.Errors)
	out.Filesystems = s.filesystems(&out.Errors)
	out.Disks = s.diskIO(&next, compatible, seconds, &out.Errors)
	out.Network = s.network(&next, compatible, seconds, &out.Errors)
	out.Processes, out.ProcessCount = s.processes(ctx, &next, compatible, seconds, &out.Errors)
	sort.Slice(out.Processes, func(i, j int) bool {
		a, b := out.Processes[i], out.Processes[j]
		if a.CPUPercent != nil && b.CPUPercent != nil && *a.CPUPercent != *b.CPUPercent {
			return *a.CPUPercent > *b.CPUPercent
		}
		if a.RSSBytes != b.RSSBytes {
			return a.RSSBytes > b.RSSBytes
		}
		return a.PID < b.PID
	})
	if len(out.Processes) > 2000 {
		out.Processes = out.Processes[:2000]
	}
	s.previous = next
	s.cached = out
	return trimSnapshot(out, limit)
}
func trimSnapshot(snapshot Snapshot, limit int) Snapshot {
	if len(snapshot.Processes) > limit {
		snapshot.Processes = snapshot.Processes[:limit]
	}
	return snapshot
}
func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return stringTrim(data)
}
func rate(current, previous uint64, seconds float64) *float64 {
	if seconds <= 0 || current < previous {
		return nil
	}
	value := float64(current-previous) / seconds
	return &value
}
