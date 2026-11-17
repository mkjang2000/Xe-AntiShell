// Package updates stages bounded enrollment-authorized RPM jobs. Applying a
// package is reserved for the independent sentinel-updater service.
package updates

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/buildinfo"
)

const (
	Directory  = "/var/lib/xe-antishell/updates"
	SocketPath = "/run/xe-antishell/sentineld.sock"
	ConfigPath = "/etc/xe-antishell/sentineld.yaml"
	HelperPath = "/usr/sbin/sentinel-updater"
	UnitPath   = "/usr/lib/systemd/system/sentinel-updater.service"
)

var ErrBusy = errors.New("busy")

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type ExecRunner struct{}
type boundedOutput struct{ buffer bytes.Buffer }

func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedOutput) Write(value []byte) (int, error) {
	if b.buffer.Len()+len(value) > 64<<10 {
		return 0, errors.New("command output limit")
	}
	return b.buffer.Write(value)
}
func (ExecRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var output boundedOutput
	cmd.Stdout = &output
	err := cmd.Run()
	return output.Bytes(), err
}

func PackageVersion(p managed.RPMPackage) string { return p.RunningVersion() }

func QueryPackage(ctx context.Context, runner Runner, artifact string) (managed.RPMPackage, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := []string{"-q", "--queryformat", "%{NAME}\\n%{EPOCHNUM}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n", "xe-antishell"}
	if artifact != "" {
		args = []string{"-qp", "--queryformat", args[2], "--", artifact}
	}
	data, err := runner.Run(bounded, "/usr/bin/rpm", args...)
	if err != nil {
		return managed.RPMPackage{}, errors.New("rpm_unavailable")
	}
	p, _, err := managed.ParseRPMMetadata(data)
	if err != nil {
		return managed.RPMPackage{}, errors.New("unsupported_package")
	}
	return p, nil
}

func HostPlatform(path string) (family, major, arch string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 16<<10 {
		return "", "", ""
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, "\"'")
		}
	}
	switch values["ID"] {
	case "rhel", "rocky", "almalinux", "centos":
		family = "rhel"
	}
	major = strings.Split(values["VERSION_ID"], ".")[0]
	switch major {
	case "7", "8", "9", "10":
	default:
		family = ""
	}
	arch = runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	return
}

// Inventory is intentionally separate from passive kernel/BPF probing.
func Inventory(ctx context.Context, runner Runner, enabled, standardPaths bool) managed.UpdateInventory {
	now := time.Now().UTC()
	family, major, arch := HostPlatform("/etc/os-release")
	i := managed.UpdateInventory{ProtocolVersion: managed.UpdateProtocolVersion, Enabled: enabled, OSFamily: family, OSMajor: major, Arch: arch, RunningVersion: buildinfo.RunningVersion(), ObservedAt: now}
	if !standardPaths {
		i.ReasonCode = "custom_paths"
		return i
	}
	if os.Geteuid() != 0 || family == "" {
		i.ReasonCode = "unsupported_platform"
		return i
	}
	if arch != "x86_64" {
		i.ReasonCode = "unsupported_arch"
		return i
	}
	if buildinfo.PackageRelease == "" || buildinfo.PackageArch != arch {
		i.ReasonCode = "unsupported_package"
		return i
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p, err := QueryPackage(bounded, runner, "")
	if err != nil {
		i.ReasonCode = "rpm_unavailable"
		return i
	}
	i.InstalledPackage = &p
	if PackageVersion(p) != i.RunningVersion {
		i.ReasonCode = "precondition_changed"
		return i
	}
	for _, path := range []string{HelperPath, UnitPath} {
		if err := secureRegular(path, 0, false); err != nil {
			i.ReasonCode = "helper_unavailable"
			return i
		}
	}
	if info, err := os.Stat(HelperPath); err != nil || info.Mode().Perm()&0o111 == 0 {
		i.ReasonCode = "helper_unavailable"
		return i
	}
	if err := secureRegular(ConfigPath, 0, false); err != nil {
		i.ReasonCode = "custom_paths"
		return i
	}
	data, err := runner.Run(bounded, "/usr/bin/systemctl", "show", "--property=LoadState", "--property=FragmentPath", "--property=DropInPaths", "sentinel-updater.service")
	if err != nil || !strings.Contains(string(data), "LoadState=loaded\n") || !strings.Contains(string(data), "FragmentPath="+UnitPath+"\n") || !strings.Contains(string(data), "DropInPaths=\n") {
		i.ReasonCode = "systemd_unavailable"
		return i
	}
	i.Supported = true
	if !enabled {
		i.ReasonCode = "disabled"
	}
	return i
}
