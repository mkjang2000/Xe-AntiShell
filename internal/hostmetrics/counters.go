package hostmetrics

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func stringTrim(data []byte) string { return strings.TrimSpace(string(data)) }
func number(value string) uint64    { n, _ := strconv.ParseUint(value, 10, 64); return n }
func (s *Sampler) cpu(next *counters, compatible bool, seconds float64, problems *[]string) *CPU {
	body, err := os.ReadFile(filepath.Join(s.proc, "stat"))
	if err != nil {
		*problems = append(*problems, "CPU counters unavailable")
		return nil
	}
	result := &CPU{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "cpu" && len(fields) >= 9 {
			for i := 1; i <= 8; i++ {
				next.total += number(fields[i])
			}
			next.idle = number(fields[4]) + number(fields[5])
		} else if strings.HasPrefix(fields[0], "cpu") {
			result.LogicalCPUs++
		}
	}
	if compatible && next.total > s.previous.total && next.idle >= s.previous.idle {
		total := next.total - s.previous.total
		idle := next.idle - s.previous.idle
		if idle <= total {
			value := 100 * float64(total-idle) / float64(total)
			result.UsagePercent = &value
		}
	}
	load := strings.Fields(readText(filepath.Join(s.proc, "loadavg")))
	if len(load) > 0 {
		result.Load1, _ = strconv.ParseFloat(load[0], 64)
	}
	return result
}
func (s *Sampler) memory(problems *[]string) *Memory {
	body, err := os.ReadFile(filepath.Join(s.proc, "meminfo"))
	if err != nil {
		*problems = append(*problems, "RAM counters unavailable")
		return nil
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			values[strings.TrimSuffix(fields[0], ":")] = number(fields[1]) * 1024
		}
	}
	total, available := values["MemTotal"], values["MemAvailable"]
	if total == 0 || available > total {
		*problems = append(*problems, "RAM counters invalid")
		return nil
	}
	if _, ok := values["MemAvailable"]; !ok {
		*problems = append(*problems, "MemAvailable not exposed")
		return nil
	}
	result := &Memory{TotalBytes: total, AvailableBytes: available, UsedBytes: total - available, SwapTotalBytes: values["SwapTotal"]}
	if values["SwapFree"] <= result.SwapTotalBytes {
		result.SwapUsedBytes = result.SwapTotalBytes - values["SwapFree"]
	}
	return result
}
func (s *Sampler) filesystems(problems *[]string) []Filesystem {
	result := []Filesystem{}
	file, err := os.Open(filepath.Join(s.proc, "mounts"))
	if err != nil {
		*problems = append(*problems, "filesystem inventory unavailable")
		return result
	}
	defer file.Close()
	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mount, kind := strings.ReplaceAll(fields[1], "\\040", " "), fields[2]
		if seen[mount] || len(result) >= 32 {
			continue
		}
		if kind != "xfs" && kind != "ext4" && kind != "ext3" && kind != "btrfs" && !(kind == "overlay" && mount == "/") {
			continue
		}
		seen[mount] = true
		var value syscall.Statfs_t
		if syscall.Statfs(mount, &value) != nil {
			continue
		}
		block := uint64(value.Bsize)
		result = append(result, Filesystem{Mount: mount, Type: kind, TotalBytes: value.Blocks * block, UsedBytes: (value.Blocks - value.Bfree) * block, AvailableBytes: value.Bavail * block, TotalInodes: value.Files, FreeInodes: value.Ffree})
	}
	return result
}
func (s *Sampler) diskIO(next *counters, compatible bool, seconds float64, problems *[]string) []DiskIO {
	result := []DiskIO{}
	body, err := os.ReadFile(filepath.Join(s.proc, "diskstats"))
	if err != nil {
		*problems = append(*problems, "disk IO counters unavailable")
		return result
	}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 || len(result) >= 128 {
			continue
		}
		name := f[2]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		cur := []uint64{number(f[3]), number(f[5]) * 512, number(f[7]), number(f[9]) * 512, number(f[12])}
		next.disks[name] = cur
		item := DiskIO{Name: name}
		if prev, ok := s.previous.disks[name]; compatible && ok {
			item.ReadIOPS = rate(cur[0], prev[0], seconds)
			item.ReadBytesPerSecond = rate(cur[1], prev[1], seconds)
			item.WriteIOPS = rate(cur[2], prev[2], seconds)
			item.WriteBytesPerSecond = rate(cur[3], prev[3], seconds)
			if busy := rate(cur[4], prev[4], seconds*10); busy != nil {
				if *busy > 100 {
					*busy = 100
				}
				item.BusyPercent = busy
			}
		}
		result = append(result, item)
	}
	return result
}
func (s *Sampler) network(next *counters, compatible bool, seconds float64, problems *[]string) []Interface {
	result := []Interface{}
	body, err := os.ReadFile(filepath.Join(s.proc, "net/dev"))
	if err != nil {
		*problems = append(*problems, "interface counters unavailable")
		return result
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || len(result) >= 256 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		f := strings.Fields(parts[1])
		if len(f) < 16 || name == "" || strings.ContainsAny(name, "/\\") {
			continue
		}
		cur := []uint64{number(f[0]), number(f[8])}
		next.network[name] = cur
		item := Interface{Name: name, State: readText(filepath.Join(s.sys, "class/net", name, "operstate")), RxBytes: cur[0], TxBytes: cur[1], RxErrors: number(f[2]), RxDropped: number(f[3]), TxErrors: number(f[10]), TxDropped: number(f[11])}
		if prev, ok := s.previous.network[name]; compatible && ok {
			item.RxBytesPerSecond = rate(cur[0], prev[0], seconds)
			item.TxBytesPerSecond = rate(cur[1], prev[1], seconds)
		}
		result = append(result, item)
	}
	return result
}
