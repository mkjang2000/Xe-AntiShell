package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/privileges"
)

func TestManagedPrivilegeCoverageRejectsSourceFilterAndProofRemoval(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	policy := managed.DefaultPolicy("agent", "enrollment", 1, time.Now())
	for _, extra := range [][]string{{"--process", "sh"}, {"--event-types=PROCESS_EXEC"}, {"-e", "PROCESS_EXEC"}, {"--include-fields", "process"}, {"-F", "process.creds"}, {"--exclude-fields", "process.arguments,process_kprobe.args"}, {"--policy-names", "another-policy"}} {
		service.config.Collector.Tetragon.Args = append([]string{"getevents", "-o", "json"}, extra...)
		policy.Detection.PrivilegeRules = false
		if err := service.validatePolicyCoverage(policy); err != nil {
			t.Fatalf("legacy policy changed for %q: %v", extra, err)
		}
		policy.Detection.PrivilegeRules = true
		if err := service.validatePolicyCoverage(policy); err == nil {
			t.Fatalf("managed opt-in accepted filter %q", extra)
		}
	}
	service.config.Collector.Tetragon.Args = []string{"getevents", "-o", "json", "--exclude-fields", "process.arguments,process.environment_variables,parent.arguments,parent.environment_variables,ancestors.arguments,ancestors.environment_variables"}
	if err := service.validatePolicyCoverage(policy); err != nil {
		t.Fatalf("installed privacy-only source rejected: %v", err)
	}
}

func TestPrivilegeEngineNeverAdvertisesSupportForNarrowedSource(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production controller requires root")
	}
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	args := []string{"--server-address", "unix:///run/tetragon/tetragon.sock", "getevents", "-o", "json"}
	service.privilegeController = privileges.New("/usr/bin/true", args, filepath.Join(t.TempDir(), "sensor"))
	if !service.privilegeController.Snapshot().Supported {
		t.Fatal("test controller lacks static support")
	}
	service.config.Collector.Tetragon.Args = args
	status := model.AgentStatus{Collector: "tetragon-json"}
	report := model.CapabilityReport{Capabilities: map[string]model.Capability{}}
	service.applyPrivilegeCapabilities(&status, &report, sourceRuntimeEvidence{}, false)
	if cap := report.Capabilities[privilegeEngineCapability]; cap.State != model.CapabilitySupported || cap.RuntimeState != "available" {
		t.Fatalf("reviewed source unavailable: %+v", cap)
	}
	service.config.Collector.Tetragon.Args = append(append([]string{}, args...), "--exclude-fields=process.creds")
	service.applyPrivilegeCapabilities(&status, &report, sourceRuntimeEvidence{}, false)
	if cap := report.Capabilities[privilegeEngineCapability]; cap.State != model.CapabilityUnsupported || cap.RuntimeState != "inactive" {
		t.Fatalf("proof removal source advertised as compatible: %+v", cap)
	}
}
