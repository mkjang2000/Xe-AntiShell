package capability

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestProbeFullModernFixture(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/os-release", "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME=\"Rocky Linux 9.6\"\n")
	writeFixture(t, root, "/proc/sys/kernel/random/boot_id", "boot-123\n")
	writeFixture(t, root, "/boot/config-5.14.0-test", "CONFIG_BPF=y\nCONFIG_BPF_SYSCALL=y\nCONFIG_BPF_EVENTS=y\nCONFIG_AUDIT=y\nCONFIG_AUDITSYSCALL=y\n")
	writeFixture(t, root, "/sys/kernel/btf/vmlinux", "btf")
	writeFixture(t, root, "/sys/kernel/security/ima/ascii_runtime_measurements", "measurements")
	writeFixture(t, root, "/dev/tpmrm0", "device")
	writeFixture(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpu memory")

	fixed := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	p := &Prober{
		Root: root,
		LookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
		Now:      func() time.Time { return fixed },
		Hostname: func() (string, error) { return "web-01", nil },
		Uname:    func() (string, string, error) { return "5.14.0-test", "x86_64", nil },
	}
	report, err := p.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.ProbedAt != fixed || report.Platform.Distribution != "rocky" || report.Platform.BootID != "boot-123" {
		t.Fatalf("unexpected platform report: %#v", report)
	}
	assertState(t, report, PlatformCapability, model.CapabilitySupported)
	assertState(t, report, BTFCapability, model.CapabilitySupported)
	assertState(t, report, EBPFCapability, model.CapabilityLimited)
	assertState(t, report, AuditCapability, model.CapabilityLimited)
	assertState(t, report, TetragonCapability, model.CapabilityLimited)
	assertState(t, report, IMACapability, model.CapabilitySupported)
	assertState(t, report, TPMCapability, model.CapabilitySupported)
	assertState(t, report, CgroupCapability, model.CapabilitySupported)
	assertState(t, report, ProcessExecCapability, model.CapabilityLimited)
	assertState(t, report, ProcessLineageCapability, model.CapabilityLimited)
	assertState(t, report, FileCapability, model.CapabilityUnsupported)
}

func TestProbeLegacyFixtureDoesNotOverclaim(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/os-release", "ID=centos\nVERSION_ID='7'\nPRETTY_NAME='CentOS Linux 7'\n")
	writeFixture(t, root, "/proc/sys/kernel/random/boot_id", "legacy-boot\n")
	writeFixture(t, root, "/boot/config-3.10.0-test", "CONFIG_AUDIT=y\nCONFIG_AUDITSYSCALL=y\n")
	writeFixture(t, root, "/dev/tpm0", "device")
	writeFixture(t, root, "/proc/cgroups", "#subsys_name\n")

	p := &Prober{
		Root: root,
		LookPath: func(name string) (string, error) {
			if name == "tetragon" {
				return "/usr/bin/tetragon", nil
			}
			return "", errors.New("not found")
		},
		Hostname: func() (string, error) { return "legacy", nil },
		Uname:    func() (string, string, error) { return "3.10.0-test", "x86_64", nil },
	}
	report, err := p.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertState(t, report, BTFCapability, model.CapabilityUnsupported)
	assertState(t, report, EBPFCapability, model.CapabilityUnsupported)
	assertState(t, report, AuditCapability, model.CapabilityLimited)
	assertState(t, report, TetragonCapability, model.CapabilityUnsupported)
	assertState(t, report, TPMCapability, model.CapabilityLimited)
	assertState(t, report, CgroupCapability, model.CapabilityLimited)
	assertState(t, report, ProcessExecCapability, model.CapabilityLimited)
	assertState(t, report, ProcessLineageCapability, model.CapabilityLimited)
}

func TestProbeConfiguredTetraOutsidePATHRemainsPassive(t *testing.T) {
	p := configuredTetraFixture(t)
	t.Setenv("PATH", t.TempDir())
	marker := filepath.Join(p.Root, "unexpected-execution")
	writeFixture(t, p.Root, p.ConfiguredTetraCommand, "#!/bin/sh\nprintf executed > '"+marker+"'\n")
	if err := os.Chmod(p.path(p.ConfiguredTetraCommand), 0o755); err != nil {
		t.Fatal(err)
	}

	report, err := p.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{TetragonCapability, EBPFCapability, ProcessExecCapability, ProcessLineageCapability} {
		assertState(t, report, name, model.CapabilityLimited)
		value := report.Capabilities[name]
		if value.RuntimeState != "" || value.VerifiedAt != nil {
			t.Fatalf("binary presence fabricated runtime evidence: %#v", value)
		}
	}
	details := report.Capabilities[TetragonCapability].Details
	if details["configured_command"] != p.ConfiguredTetraCommand || details["tetra"] != p.path(p.ConfiguredTetraCommand) {
		t.Fatalf("configured client evidence missing: %#v", details)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("passive probe executed the configured command: %v", err)
	}
}

func TestProbeConfiguredTetraDoesNotFallBackToPATH(t *testing.T) {
	for _, condition := range []string{"missing", "non-executable", "directory", "relative"} {
		t.Run(condition, func(t *testing.T) {
			p := configuredTetraFixture(t)
			for _, name := range []string{"tetra", "tetragon"} {
				path := "/usr/bin/" + name
				writeFixture(t, p.Root, path, "unrelated executable")
				if err := os.Chmod(p.path(path), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", p.path("/usr/bin"))
			if _, err := exec.LookPath("tetra"); err != nil {
				t.Fatalf("PATH fallback fixture is not executable: %v", err)
			}
			switch condition {
			case "non-executable":
				writeFixture(t, p.Root, p.ConfiguredTetraCommand, "not executable")
			case "directory":
				if err := os.MkdirAll(p.path(p.ConfiguredTetraCommand), 0o755); err != nil {
					t.Fatal(err)
				}
			case "relative":
				p.ConfiguredTetraCommand = "tetra"
			}

			report, err := p.Probe(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			assertState(t, report, TetragonCapability, model.CapabilityUnsupported)
			value := report.Capabilities[TetragonCapability]
			if value.Details["configured_command"] != p.ConfiguredTetraCommand || value.Details["tetra"] != "" || value.Details["tetragon"] != "" {
				t.Fatalf("an unrelated PATH executable satisfied the configured client: %#v", value)
			}
		})
	}
}

func TestProbeConfiguredTetraStillRequiresKernelPrerequisites(t *testing.T) {
	for _, condition := range []string{"old-kernel", "missing-btf"} {
		t.Run(condition, func(t *testing.T) {
			p := configuredTetraFixture(t)
			writeFixture(t, p.Root, p.ConfiguredTetraCommand, "executable client")
			if err := os.Chmod(p.path(p.ConfiguredTetraCommand), 0o755); err != nil {
				t.Fatal(err)
			}
			wantReason := "minimum 4.19"
			if condition == "old-kernel" {
				p.Uname = func() (string, string, error) { return "4.18.0-test", "x86_64", nil }
			} else {
				if err := os.Remove(p.path("/sys/kernel/btf/vmlinux")); err != nil {
					t.Fatal(err)
				}
				wantReason = "BTF is unavailable"
			}

			report, err := p.Probe(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			assertState(t, report, TetragonCapability, model.CapabilityUnsupported)
			value := report.Capabilities[TetragonCapability]
			if !strings.Contains(value.Reason, wantReason) || value.Details["tetra"] == "" {
				t.Fatalf("configured client bypassed kernel prerequisites: %#v", value)
			}
		})
	}
}

func configuredTetraFixture(t *testing.T) *Prober {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "/etc/os-release", "ID=rocky\nVERSION_ID=9.6\n")
	writeFixture(t, root, "/proc/sys/kernel/random/boot_id", "configured-boot\n")
	writeFixture(t, root, "/boot/config-5.14.0-test", "CONFIG_BPF=y\nCONFIG_BPF_SYSCALL=y\nCONFIG_BPF_EVENTS=y\n")
	writeFixture(t, root, "/sys/kernel/btf/vmlinux", "btf")
	return &Prober{
		Root:                   root,
		ConfiguredTetraCommand: "/opt/xe-antishell/tetragon/v1.8.0/tetra",
		Hostname:               func() (string, error) { return "configured-host", nil },
		Uname:                  func() (string, string, error) { return "5.14.0-test", "x86_64", nil },
	}
}

func TestProbeSurfacesMissingPlatformEvidence(t *testing.T) {
	p := &Prober{
		Root:     t.TempDir(),
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
		Hostname: func() (string, error) { return "", errors.New("hostname unavailable") },
		Uname:    func() (string, string, error) { return "", "", errors.New("uname unavailable") },
	}
	report, err := p.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertState(t, report, PlatformCapability, model.CapabilityError)
}

func TestProbeHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewProber().Probe(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context, got %v", err)
	}
}

func TestProbeReadsProcConfigGzipFallback(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/os-release", "ID=rocky\nVERSION_ID=8.10\n")
	writeFixture(t, root, "/proc/sys/kernel/random/boot_id", "boot-gzip\n")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("CONFIG_BPF=y\nCONFIG_BPF_SYSCALL=y\nCONFIG_BPF_EVENTS=y\nCONFIG_AUDIT=y\nCONFIG_AUDITSYSCALL=y\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "/proc/config.gz", compressed.String())
	p := &Prober{
		Root:     root,
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
		Hostname: func() (string, error) { return "gzip-host", nil },
		Uname:    func() (string, string, error) { return "4.18.0-test", "x86_64", nil },
	}
	report, err := p.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertState(t, report, EBPFCapability, model.CapabilityLimited)
	assertState(t, report, AuditCapability, model.CapabilityLimited)
}

func TestKernelAtLeast(t *testing.T) {
	for _, test := range []struct {
		release string
		want    bool
	}{
		{"4.18.0-553.el8", false},
		{"4.19.0", true},
		{"5.14.0-70", true},
		{"invalid", false},
	} {
		if got := kernelAtLeast(test.release, 4, 19); got != test.want {
			t.Errorf("kernelAtLeast(%q) = %v, want %v", test.release, got, test.want)
		}
	}
}

func writeFixture(t *testing.T, root, path, contents string) {
	t.Helper()
	fullPath := filepath.Join(root, path[1:])
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertState(t *testing.T, report model.CapabilityReport, name string, want model.CapabilityState) {
	t.Helper()
	capability, ok := report.Capability(name)
	if !ok {
		t.Fatalf("capability %q missing", name)
	}
	if capability.State != want {
		t.Fatalf("capability %q state = %q, want %q: %#v", name, capability.State, want, capability)
	}
}
