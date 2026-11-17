// Package capability performs passive host feature discovery. Operational
// collector startup remains the authoritative check for features that require
// privileges or kernel attachment.
package capability

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"xe-antishell/internal/model"
)

const (
	ProbeVersion = "0.1"

	PlatformCapability       = "host.platform"
	BTFCapability            = "kernel.btf"
	EBPFCapability           = "kernel.ebpf"
	AuditCapability          = "collector.audit"
	TetragonCapability       = "collector.tetragon"
	IMACapability            = "integrity.ima"
	TPMCapability            = "integrity.tpm"
	CgroupCapability         = "kernel.cgroup"
	ProcessExecCapability    = "observation.process_exec"
	ProcessLineageCapability = "observation.process_lineage"
	CredentialCapability     = "observation.credential_change"
	FileCapability           = "observation.file"
	NetworkCapability        = "observation.network"
)

type UnameFunc func() (release, architecture string, err error)

type Prober struct {
	// Root remaps absolute probe paths and is intended for tests and offline
	// image inspection. An empty Root probes the running host.
	Root     string
	LookPath func(string) (string, error)
	Now      func() time.Time
	Hostname func() (string, error)
	Uname    UnameFunc
	// ConfiguredTetraCommand is the agent's absolute event-client path. When
	// supplied, another executable on PATH cannot satisfy this prerequisite.
	ConfiguredTetraCommand string
}

func NewProber() *Prober {
	return &Prober{
		LookPath: exec.LookPath,
		Now:      time.Now,
		Hostname: os.Hostname,
		Uname:    uname,
	}
}

func (p *Prober) Probe(ctx context.Context) (model.CapabilityReport, error) {
	if err := ctx.Err(); err != nil {
		return model.CapabilityReport{}, err
	}
	if p == nil {
		p = NewProber()
	}
	lookPath := p.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	hostname := p.Hostname
	if hostname == nil {
		hostname = os.Hostname
	}
	unameFn := p.Uname
	if unameFn == nil {
		unameFn = uname
	}

	report := model.CapabilityReport{
		ProbeVersion: ProbeVersion,
		ProbedAt:     now().UTC(),
		Capabilities: make(map[string]model.Capability),
	}

	platform, platformCapability := p.probePlatform(hostname, unameFn)
	report.Platform = platform
	report.Capabilities[PlatformCapability] = platformCapability

	btf := p.probeBTF()
	report.Capabilities[BTFCapability] = btf
	report.Capabilities[EBPFCapability] = p.probeEBPF(platform.KernelRelease, btf)
	report.Capabilities[AuditCapability] = p.probeAudit(platform.KernelRelease)
	report.Capabilities[TetragonCapability] = p.probeTetragon(platform.KernelRelease, btf, lookPath)
	report.Capabilities[IMACapability] = p.probeIMA()
	report.Capabilities[TPMCapability] = p.probeTPM(lookPath)
	report.Capabilities[CgroupCapability] = p.probeCgroup()
	p.deriveObservationCapabilities(&report)

	if err := ctx.Err(); err != nil {
		return model.CapabilityReport{}, err
	}
	return report, nil
}

func (p *Prober) deriveObservationCapabilities(report *model.CapabilityReport) {
	tetragon := report.Capabilities[TetragonCapability]
	audit := report.Capabilities[AuditCapability]
	provider := "passive-probe"
	reason := "no usable process event source was found"
	lineageReason := reason
	state := model.CapabilityUnsupported
	if tetragon.State == model.CapabilitySupported || tetragon.State == model.CapabilityLimited {
		provider = "tetragon"
		reason = "Tetragon candidate found; collector startup must verify process coverage"
		lineageReason = "Tetragon candidate found; collector startup must verify lineage coverage"
		state = model.CapabilityLimited
	} else if audit.State == model.CapabilitySupported || audit.State == model.CapabilityLimited {
		provider = "audit"
		reason = "audit candidate found; dispatcher connection and exec rules must be verified"
		lineageReason = "audit candidate found; lineage remains derived and dispatcher coverage must be verified"
		state = model.CapabilityLimited
	}
	report.Capabilities[ProcessExecCapability] = capability(ProcessExecCapability, state, provider, reason, nil)
	report.Capabilities[ProcessLineageCapability] = capability(ProcessLineageCapability, state, provider, lineageReason, nil)
	report.Capabilities[CredentialCapability] = capability(CredentialCapability, model.CapabilityUnsupported,
		"standalone-mvp", "credential-change collection is not implemented in this MVP", nil)
	report.Capabilities[FileCapability] = capability(FileCapability, model.CapabilityUnsupported,
		"standalone-mvp", "file observation is not implemented in this MVP", nil)
	report.Capabilities[NetworkCapability] = capability(NetworkCapability, model.CapabilityUnsupported,
		"standalone-mvp", "network observation is not implemented in this MVP", nil)
}

func (p *Prober) probePlatform(hostname func() (string, error), unameFn UnameFunc) (model.Platform, model.Capability) {
	platform := model.Platform{}
	details := make(map[string]string)
	var problems []string

	values, err := p.readOSRelease()
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		platform.Distribution = values["ID"]
		platform.VersionID = values["VERSION_ID"]
		platform.PrettyName = values["PRETTY_NAME"]
	}

	release, architecture, err := unameFn()
	if err != nil {
		problems = append(problems, "uname: "+err.Error())
	} else {
		platform.KernelRelease = release
		platform.Architecture = architecture
	}

	bootID, err := p.readTrimmed("/proc/sys/kernel/random/boot_id", 4096)
	if err != nil {
		problems = append(problems, "boot ID: "+err.Error())
	} else {
		platform.BootID = bootID
	}

	name, err := hostname()
	if err != nil {
		problems = append(problems, "hostname: "+err.Error())
	} else {
		platform.Hostname = name
	}

	if len(problems) != 0 {
		details["problems"] = strings.Join(problems, "; ")
		return platform, capability(PlatformCapability, model.CapabilityError, "passive-probe", "one or more platform identifiers could not be read", details)
	}
	return platform, capability(PlatformCapability, model.CapabilitySupported, "passive-probe", "platform identifiers read successfully", nil)
}

func (p *Prober) probeBTF() model.Capability {
	const btfPath = "/sys/kernel/btf/vmlinux"
	if err := p.existsFile(btfPath); err == nil {
		return capability(BTFCapability, model.CapabilitySupported, btfPath, "kernel BTF is exposed", map[string]string{"path": btfPath})
	} else if !errors.Is(err, os.ErrNotExist) {
		return capability(BTFCapability, model.CapabilityError, btfPath, err.Error(), nil)
	}
	return capability(BTFCapability, model.CapabilityUnsupported, "passive-probe", "kernel BTF was not found", nil)
}

func (p *Prober) probeEBPF(kernelRelease string, btf model.Capability) model.Capability {
	config, configPath, err := p.readKernelConfig(kernelRelease)
	if err != nil {
		return capability(EBPFCapability, model.CapabilityLimited, "passive-probe", "kernel configuration unavailable; runtime attach probe is required", map[string]string{"btf": string(btf.State)})
	}
	required := []string{"CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_EVENTS"}
	var missing []string
	for _, name := range required {
		if config[name] != "y" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return capability(EBPFCapability, model.CapabilityUnsupported, configPath, "required eBPF kernel options are missing", map[string]string{"missing": strings.Join(missing, ",")})
	}
	details := map[string]string{"kernel_config": configPath, "btf": string(btf.State)}
	return capability(EBPFCapability, model.CapabilityLimited, configPath, "passive checks passed; collector startup must verify load and attach", details)
}

func (p *Prober) probeAudit(kernelRelease string) model.Capability {
	config, configPath, err := p.readKernelConfig(kernelRelease)
	if err == nil {
		if config["CONFIG_AUDIT"] != "y" || config["CONFIG_AUDITSYSCALL"] != "y" {
			return capability(AuditCapability, model.CapabilityUnsupported, configPath, "kernel audit syscall support is not enabled", nil)
		}
		return capability(AuditCapability, model.CapabilityLimited, configPath, "kernel audit support is present; dispatcher ownership must be verified at startup", map[string]string{"kernel_config": configPath})
	}

	for _, path := range []string{"/run/auditd.pid", "/var/run/auditd.pid", "/sbin/auditd", "/usr/sbin/auditd"} {
		if p.existsFile(path) == nil {
			return capability(AuditCapability, model.CapabilityLimited, path, "audit userspace evidence found; kernel and dispatcher access must be verified", map[string]string{"path": path})
		}
	}
	return capability(AuditCapability, model.CapabilityUnsupported, "passive-probe", "no audit kernel configuration or userspace evidence was found", nil)
}

func (p *Prober) probeTetragon(kernelRelease string, btf model.Capability, lookPath func(string) (string, error)) model.Capability {
	details := make(map[string]string)
	if command := p.ConfiguredTetraCommand; command != "" {
		details["configured_command"] = command
		if !filepath.IsAbs(command) {
			return capability(TetragonCapability, model.CapabilityUnsupported, "passive-probe", "configured tetra command must be an absolute path", details)
		}
		path, err := lookPath(p.path(command))
		if err != nil {
			details["command_error"] = err.Error()
			return capability(TetragonCapability, model.CapabilityUnsupported, "passive-probe", "configured tetra executable was not found or is not executable", details)
		}
		details["tetra"] = path
	} else {
		if path, err := lookPath("tetragon"); err == nil {
			details["tetragon"] = path
		}
		if path, err := lookPath("tetra"); err == nil {
			details["tetra"] = path
		}
		if len(details) == 0 {
			return capability(TetragonCapability, model.CapabilityUnsupported, "passive-probe", "neither tetragon nor tetra executable was found", nil)
		}
	}
	if !kernelAtLeast(kernelRelease, 4, 19) {
		return capability(TetragonCapability, model.CapabilityUnsupported, "passive-probe", "kernel is below Tetragon's minimum 4.19 requirement", details)
	}
	if btf.State != model.CapabilitySupported {
		return capability(TetragonCapability, model.CapabilityUnsupported, "passive-probe", "Tetragon executable exists but kernel BTF is unavailable", details)
	}
	return capability(TetragonCapability, model.CapabilityLimited, "passive-probe", "binary and passive kernel requirements found; startup must verify operation", details)
}

func (p *Prober) probeIMA() model.Capability {
	const measurementPath = "/sys/kernel/security/ima/ascii_runtime_measurements"
	if err := p.existsFile(measurementPath); err == nil {
		return capability(IMACapability, model.CapabilitySupported, measurementPath, "IMA runtime measurements are exposed", map[string]string{"path": measurementPath})
	} else if !errors.Is(err, os.ErrNotExist) {
		return capability(IMACapability, model.CapabilityError, measurementPath, err.Error(), nil)
	}
	if err := p.existsDirectory("/sys/kernel/security/ima"); err == nil {
		return capability(IMACapability, model.CapabilityLimited, "/sys/kernel/security/ima", "IMA directory exists but runtime measurements are not exposed", nil)
	} else if !errors.Is(err, os.ErrNotExist) {
		return capability(IMACapability, model.CapabilityError, "/sys/kernel/security/ima", err.Error(), nil)
	}
	return capability(IMACapability, model.CapabilityUnsupported, "passive-probe", "IMA securityfs entries were not found", nil)
}

func (p *Prober) probeTPM(lookPath func(string) (string, error)) model.Capability {
	if err := p.existsFile("/dev/tpmrm0"); err == nil {
		details := map[string]string{"device": "/dev/tpmrm0"}
		if tool, toolErr := lookPath("tpm2_getcap"); toolErr == nil {
			details["tpm2_getcap"] = tool
		}
		return capability(TPMCapability, model.CapabilitySupported, "/dev/tpmrm0", "TPM resource-manager device is present", details)
	} else if !errors.Is(err, os.ErrNotExist) {
		return capability(TPMCapability, model.CapabilityError, "/dev/tpmrm0", err.Error(), nil)
	}
	if err := p.existsFile("/dev/tpm0"); err == nil {
		return capability(TPMCapability, model.CapabilityLimited, "/dev/tpm0", "TPM device exists, but TPM 2.0 and resource-manager support are unverified", map[string]string{"device": "/dev/tpm0"})
	} else if !errors.Is(err, os.ErrNotExist) {
		return capability(TPMCapability, model.CapabilityError, "/dev/tpm0", err.Error(), nil)
	}
	return capability(TPMCapability, model.CapabilityUnsupported, "passive-probe", "no TPM device was found", nil)
}

func (p *Prober) probeCgroup() model.Capability {
	if err := p.existsFile("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return capability(CgroupCapability, model.CapabilitySupported, "cgroupfs", "cgroup v2 unified hierarchy detected", map[string]string{"version": "2"})
	} else if !errors.Is(err, os.ErrNotExist) {
		return capability(CgroupCapability, model.CapabilityError, "cgroupfs", err.Error(), nil)
	}
	if err := p.existsFile("/proc/cgroups"); err == nil {
		return capability(CgroupCapability, model.CapabilityLimited, "procfs", "cgroup v1 or hybrid hierarchy detected", map[string]string{"version": "1-or-hybrid"})
	} else if !errors.Is(err, os.ErrNotExist) {
		return capability(CgroupCapability, model.CapabilityError, "procfs", err.Error(), nil)
	}
	return capability(CgroupCapability, model.CapabilityUnsupported, "passive-probe", "cgroup interfaces were not found", nil)
}

func (p *Prober) readOSRelease() (map[string]string, error) {
	data, err := p.readFile("/etc/os-release", 128<<10)
	if err != nil {
		return nil, fmt.Errorf("os-release: %w", err)
	}
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		} else if strings.HasPrefix(value, "\"") {
			unquoted, unquoteErr := strconv.Unquote(value)
			if unquoteErr != nil {
				return nil, fmt.Errorf("os-release key %s: %w", key, unquoteErr)
			}
			value = unquoted
		}
		result[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("os-release: %w", err)
	}
	if result["ID"] == "" {
		return nil, errors.New("os-release: ID is missing")
	}
	return result, nil
}

func (p *Prober) readKernelConfig(kernelRelease string) (map[string]string, string, error) {
	if kernelRelease == "" {
		return nil, "", errors.New("kernel release is unknown")
	}
	if len(kernelRelease) > 255 || strings.ContainsAny(kernelRelease, "/\\\x00") {
		return nil, "", errors.New("kernel release contains invalid path characters")
	}
	logicalPath := "/boot/config-" + kernelRelease
	data, err := p.readFile(logicalPath, 8<<20)
	if err != nil {
		compressedPath := "/proc/config.gz"
		compressed, compressedErr := p.readFile(compressedPath, 8<<20)
		if compressedErr != nil {
			return nil, logicalPath, err
		}
		reader, gzipErr := gzip.NewReader(bytes.NewReader(compressed))
		if gzipErr != nil {
			return nil, compressedPath, gzipErr
		}
		decompressed, readErr := io.ReadAll(io.LimitReader(reader, (8<<20)+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, compressedPath, readErr
		}
		if closeErr != nil {
			return nil, compressedPath, closeErr
		}
		if len(decompressed) > 8<<20 {
			return nil, compressedPath, errors.New("decompressed kernel config exceeds 8 MiB")
		}
		data = decompressed
		logicalPath = compressedPath
	}
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CONFIG_") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	return values, logicalPath, scanner.Err()
}

func (p *Prober) readTrimmed(path string, limit int64) (string, error) {
	data, err := p.readFile(path, limit)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", errors.New("value is empty")
	}
	return value, nil
}

func (p *Prober) readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(p.path(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := io.LimitReader(f, limit+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte probe limit", limit)
	}
	return data, nil
}

func (p *Prober) existsFile(path string) error {
	info, err := os.Stat(p.path(path))
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}

func (p *Prober) existsDirectory(path string) error {
	info, err := os.Stat(p.path(path))
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func (p *Prober) path(path string) string {
	if p.Root == "" {
		return path
	}
	return filepath.Join(p.Root, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}

func capability(name string, state model.CapabilityState, provider, reason string, details map[string]string) model.Capability {
	return model.Capability{Name: name, State: state, Provider: provider, Reason: reason, Details: details}
}

func kernelAtLeast(release string, wantMajor, wantMinor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minorDigits := parts[1]
	for i, r := range minorDigits {
		if r < '0' || r > '9' {
			minorDigits = minorDigits[:i]
			break
		}
	}
	minor, err := strconv.Atoi(minorDigits)
	if err != nil {
		return false
	}
	return major > wantMajor || major == wantMajor && minor >= wantMinor
}

func uname() (string, string, error) {
	var value syscall.Utsname
	if err := syscall.Uname(&value); err != nil {
		return "", "", err
	}
	return chars(value.Release[:]), chars(value.Machine[:]), nil
}

func chars(values []int8) string {
	bytes := make([]byte, 0, len(values))
	for _, value := range values {
		if value == 0 {
			break
		}
		bytes = append(bytes, byte(value))
	}
	return string(bytes)
}
