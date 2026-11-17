package updates

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xe-antishell/internal/buildinfo"
)

type outputRunner struct {
	output  string
	args    []string
	command string
}

func (r *outputRunner) Run(_ context.Context, command string, args ...string) ([]byte, error) {
	r.command, r.args = command, args
	return []byte(r.output), nil
}

func TestRPMHeaderParsingRejectsAmbiguousAndUnsupportedMetadata(t *testing.T) {
	for _, output := range []string{"xe-antishell\n-1\n0.1.0\n23.el9\nx86_64\n", "other\n0\n0.1.0\n23.el9\nx86_64\n", "xe-antishell\n0\n0.1.0\n23.el9\naarch64\n", "xe-antishell\n0\n0.1.0\n23.el9\nx86_64\nextra\n"} {
		runner := &outputRunner{output: output}
		if _, err := QueryPackage(context.Background(), runner, "/private/artifact.rpm"); err == nil {
			t.Fatal("unsupported package metadata accepted")
		}
		if runner.command != "/usr/bin/rpm" || strings.Join(runner.args[len(runner.args)-2:], " ") != "-- /private/artifact.rpm" {
			t.Fatal("package path was not a bounded RPM argument")
		}
	}
	runner := &outputRunner{output: "xe-antishell\n2\n0.1.0\n23.el9\nx86_64\n"}
	packageInfo, err := QueryPackage(context.Background(), runner, "")
	if err != nil || PackageVersion(packageInfo) != "2:0.1.0-23.el9.x86_64" {
		t.Fatalf("epoch lost from installed identity: %#v %v", packageInfo, err)
	}
}

func TestInventorySourceAndCustomPathsDoNotRunInstallationProbes(t *testing.T) {
	runner := &outputRunner{}
	inventory := Inventory(context.Background(), runner, true, false)
	if inventory.Supported || inventory.ReasonCode != "custom_paths" || runner.command != "" {
		t.Fatal("custom source configuration ran update commands")
	}
	if buildinfo.PackageRelease == "" {
		inventory = Inventory(context.Background(), runner, true, true)
		if inventory.Supported || runner.command != "" {
			t.Fatal("development build probed package management")
		}
	}
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("ID=rocky\nVERSION_ID=\"9.8\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	family, major, _ := HostPlatform(path)
	if family != "rhel" || major != "9" {
		t.Fatal("EL userspace major was inferred incorrectly")
	}
}

func TestCommandOutputBoundCannotBeBypassedByCopyReaderFrom(t *testing.T) {
	var output boundedOutput
	// Hide the source's WriterTo so io.Copy tests the destination's interfaces.
	source := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 64<<10+1))}
	if _, err := io.Copy(&output, source); err == nil {
		t.Fatal("oversized command output bypassed Write")
	}
	if len(output.Bytes()) > 64<<10 {
		t.Fatal("command output exceeded memory limit")
	}
}
