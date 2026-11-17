package hostmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSamplerFirstAndSecondSamples(t *testing.T) {
	sampler := metricFixture(t)
	first := sampler.Sample(context.Background(), 10)
	assertUnknownRates(t, first)
	if first.IntervalSeconds != 0 || first.CPU.LogicalCPUs != 2 || first.CPU.Load1 != 1.25 {
		t.Fatalf("first CPU sample: %#v, interval %v", first.CPU, first.IntervalSeconds)
	}
	if first.Memory.UsedBytes != 768*1024 || first.Memory.SwapUsedBytes != 128*1024 {
		t.Fatalf("memory sample: %#v", first.Memory)
	}
	if len(first.Errors) != 0 || len(first.Processes) != 1 {
		t.Fatalf("unexpected sample: %#v", first)
	}
	process := first.Processes[0]
	if process.PID != 100 || process.PPID != 1 || process.UID != 1000 || process.OriginService != "web.service" || process.Exe != "/usr/bin/php-fpm" || process.RSSBytes != uint64(os.Getpagesize()*4) {
		t.Fatalf("process metadata: %#v", process)
	}
	fixtureWrite(t, sampler.proc, "stat", "cpu 180 0 120 900 0 0 0 0 0 0\ncpu0 1 0 1 1\ncpu1 1 0 1 1\n")
	fixtureWrite(t, sampler.proc, "diskstats", "8 0 vda 20 0 120 0 24 0 240 0 0 1200 0\n")
	fixtureWrite(t, sampler.proc, "net/dev", "eth0: 3000 0 2 3 0 0 0 0 5000 0 4 5 0 0 0 0\n")
	fixtureProcess(t, sampler.proc, 100, 500, 50, 20, 4)
	expireMetricCache(sampler)
	second := sampler.Sample(context.Background(), 10)
	seconds := second.IntervalSeconds
	if seconds < 1.9 || math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		t.Fatalf("unexpected sample interval: %v", seconds)
	}
	assertMetric(t, "CPU percent", second.CPU.UsagePercent, 50)
	assertMetric(t, "disk reads/s", second.Disks[0].ReadIOPS, 10/seconds)
	assertMetric(t, "disk writes/s", second.Disks[0].WriteIOPS, 4/seconds)
	assertMetric(t, "disk read B/s", second.Disks[0].ReadBytesPerSecond, 20*512/seconds)
	assertMetric(t, "disk write B/s", second.Disks[0].WriteBytesPerSecond, 40*512/seconds)
	assertMetric(t, "disk busy percent", second.Disks[0].BusyPercent, 200/(seconds*10))
	assertMetric(t, "network RX B/s", second.Network[0].RxBytesPerSecond, 2000/seconds)
	assertMetric(t, "network TX B/s", second.Network[0].TxBytesPerSecond, 3000/seconds)
	assertMetric(t, "process CPU percent", second.Processes[0].CPUPercent, 50/seconds)
	if second.Network[0].State != "up" || second.Network[0].RxErrors != 2 || second.Network[0].TxDropped != 5 {
		t.Fatalf("interface metadata: %#v", second.Network[0])
	}
}

func TestSamplerCounterResetBootChangeAndPIDReuse(t *testing.T) {
	for _, scenario := range []string{"counter-reset", "boot-change", "pid-reuse"} {
		t.Run(scenario, func(t *testing.T) {
			sampler := metricFixture(t)
			sampler.Sample(context.Background(), 10)
			switch scenario {
			case "counter-reset":
				fixtureWrite(t, sampler.proc, "stat", "cpu 1 0 1 8 0 0 0 0\ncpu0 1 0 1 8\n")
				fixtureWrite(t, sampler.proc, "diskstats", "8 0 vda 1 0 1 0 1 0 1 0 0 1 0\n")
				fixtureWrite(t, sampler.proc, "net/dev", "eth0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n")
				fixtureProcess(t, sampler.proc, 100, 500, 1, 1, 4)
			case "boot-change":
				fixtureWrite(t, sampler.proc, "sys/kernel/random/boot_id", "boot-b\n")
			case "pid-reuse":
				fixtureProcess(t, sampler.proc, 100, 900, 1000, 1000, 4)
			}
			expireMetricCache(sampler)
			sample := sampler.Sample(context.Background(), 10)
			if scenario == "pid-reuse" {
				if sample.Processes[0].StartTicks != 900 || sample.Processes[0].CPUPercent != nil {
					t.Fatalf("PID reuse inherited previous CPU counters: %#v", sample.Processes[0])
				}
				return
			}
			assertUnknownRates(t, sample)
			if scenario == "boot-change" && sample.IntervalSeconds != 0 {
				t.Fatalf("cross-boot interval is trusted: %v", sample.IntervalSeconds)
			}
		})
	}
}

func TestSamplerCacheLimitAndMissingCounters(t *testing.T) {
	sampler := metricFixture(t)
	fixtureProcess(t, sampler.proc, 101, 600, 1, 1, 10)
	first := sampler.Sample(context.Background(), 1)
	if len(first.Processes) != 1 || first.ProcessCount != 2 || first.Processes[0].PID != 101 {
		t.Fatalf("bounded process snapshot must prefer greater RSS: %#v", first)
	}
	cached := sampler.Sample(context.Background(), 10)
	if !cached.SampledAt.Equal(first.SampledAt) || len(cached.Processes) != 2 {
		t.Fatalf("limited request changed full cached snapshot: %#v", cached)
	}
	fixtureWrite(t, sampler.proc, "meminfo", "MemTotal: 1024 kB\n")
	if err := os.Remove(filepath.Join(sampler.proc, "stat")); err != nil {
		t.Fatal(err)
	}
	expireMetricCache(sampler)
	missing := sampler.Sample(context.Background(), 10)
	if missing.CPU != nil || missing.Memory != nil || len(missing.Errors) < 2 {
		t.Fatalf("missing counters must be explicit, not zero usage: %#v", missing)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	expireMetricCache(sampler)
	cancelled := sampler.Sample(ctx, 10)
	if len(cancelled.Processes) != 0 || !strings.Contains(strings.Join(cancelled.Errors, " "), "cancelled") {
		t.Fatalf("cancelled process sampling: %#v", cancelled)
	}
}

func TestSamplerNeverOpensProcessArgumentsOrEnvironment(t *testing.T) {
	sampler := metricFixture(t)
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		t.Fatalf("create process privacy watch: %v", err)
	}
	defer syscall.Close(fd)
	for _, name := range []string{"cmdline", "environ"} {
		fixtureWrite(t, sampler.proc, "100/"+name, "PRIVATE_METRICS_TEST_SECRET\x00")
		if _, err := syscall.InotifyAddWatch(fd, filepath.Join(sampler.proc, "100", name), syscall.IN_OPEN|syscall.IN_ACCESS); err != nil {
			t.Fatal(err)
		}
	}
	sample := sampler.Sample(context.Background(), 10)
	var events [4096]byte
	n, err := syscall.Read(fd, events[:])
	if n > 0 || err != syscall.EAGAIN {
		t.Fatalf("sampler opened/read process cmdline or environment: bytes=%d error=%v", n, err)
	}
	raw, err := json.Marshal(sample)
	if err != nil || strings.Contains(string(raw), "PRIVATE_METRICS_TEST_SECRET") {
		t.Fatalf("process secret entered metrics JSON: %v", err)
	}
}

func TestSamplerFilesystemInventoryHandlesEscapedDuplicateMounts(t *testing.T) {
	sampler := metricFixture(t)
	mount := filepath.Join(t.TempDir(), "data volume")
	if err := os.Mkdir(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	escaped := strings.ReplaceAll(mount, " ", "\\040")
	fixtureWrite(t, sampler.proc, "mounts", fmt.Sprintf("none /proc proc rw 0 0\n/dev/vda %s ext4 rw 0 0\n/dev/vda %s ext4 rw 0 0\n", escaped, escaped))
	sample := sampler.Sample(context.Background(), 10)
	if len(sample.Filesystems) != 1 {
		t.Fatalf("duplicate/virtual mount inventory: %#v", sample.Filesystems)
	}
	filesystem := sample.Filesystems[0]
	if filesystem.Mount != mount || filesystem.TotalBytes == 0 || filesystem.UsedBytes > filesystem.TotalBytes || filesystem.AvailableBytes > filesystem.TotalBytes {
		t.Fatalf("filesystem capacity or escaped mount: %#v", filesystem)
	}
}

func metricFixture(t *testing.T) *Sampler {
	t.Helper()
	root := t.TempDir()
	proc, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	fixtureWrite(t, proc, "sys/kernel/random/boot_id", "boot-a\n")
	fixtureWrite(t, proc, "stat", "cpu 100 0 100 800 0 0 0 0 0 0\ncpu0 1 0 1 1\ncpu1 1 0 1 1\n")
	fixtureWrite(t, proc, "loadavg", "1.25 0.50 0.25 1/100 100\n")
	fixtureWrite(t, proc, "meminfo", "MemTotal: 1024 kB\nMemAvailable: 256 kB\nSwapTotal: 512 kB\nSwapFree: 384 kB\n")
	fixtureWrite(t, proc, "mounts", "")
	fixtureWrite(t, proc, "diskstats", "8 0 vda 10 0 100 0 20 0 200 0 0 1000 0\n")
	fixtureWrite(t, proc, "net/dev", "eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n")
	fixtureWrite(t, sys, "class/net/eth0/operstate", "up\n")
	fixtureProcess(t, proc, 100, 500, 10, 10, 4)
	return New(proc, sys)
}

func fixtureWrite(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixtureProcess(t *testing.T, proc string, pid int, start, user, system, rss uint64) {
	t.Helper()
	fields := strings.Fields("S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0")
	for index, value := range map[int]uint64{11: user, 12: system, 19: start, 21: rss} {
		fields[index] = strconv.FormatUint(value, 10)
	}
	root := strconv.Itoa(pid)
	fixtureWrite(t, proc, root+"/stat", fmt.Sprintf("%d (worker (test)) %s\n", pid, strings.Join(fields, " ")))
	fixtureWrite(t, proc, root+"/status", "Name:\tworker\nUid:\t1000\t1000\t1000\t1000\n")
	fixtureWrite(t, proc, root+"/cgroup", "0::/system.slice/web.service\n")
	link := filepath.Join(proc, root, "exe")
	if err := os.Symlink("/usr/bin/php-fpm", link); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
}

func expireMetricCache(sampler *Sampler) {
	sampler.cached.SampledAt = time.Time{}
	sampler.previous.at = time.Now().Add(-2 * time.Second)
}

func assertMetric(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil || math.IsNaN(*got) || math.Abs(*got-want) > 1e-7 {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func assertUnknownRates(t *testing.T, sample Snapshot) {
	t.Helper()
	if sample.CPU == nil || sample.CPU.UsagePercent != nil || len(sample.Disks) != 1 || sample.Disks[0].ReadBytesPerSecond != nil || sample.Disks[0].WriteBytesPerSecond != nil || sample.Disks[0].BusyPercent != nil || len(sample.Network) != 1 || sample.Network[0].RxBytesPerSecond != nil || sample.Network[0].TxBytesPerSecond != nil || len(sample.Processes) != 1 || sample.Processes[0].CPUPercent != nil {
		t.Fatalf("untrusted counter delta produced a usage rate: %#v", sample)
	}
}
