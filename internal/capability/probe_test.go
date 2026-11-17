package capability

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
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
