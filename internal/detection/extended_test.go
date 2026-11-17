package detection

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

func extendedEngine(allowed ...string) *Engine {
	return NewWithOptions(Options{
		WebExecutables: []string{"nginx"}, WebServices: []string{"shop.service"},
		Shells: []string{"sh", "bash"}, AllowedPairs: allowed, ExtendedProcessRules: true,
	})
}

func extendedEvent(exe string, args ...string) model.Event {
	return model.Event{
		ID: "extended-event", Type: "process.exec", Source: "audit", BootID: "boot",
		EventTime: time.Unix(1700000000, 0).UTC(),
		Process: model.Process{
			Key: "process-key", PID: 101, PPID: 100, Exe: exe,
			Argv: append([]string{exe}, args...), EUID: 1000, UID: 1000,
			OriginService: "shop.service", LineageConfidence: model.LineageVerified,
		},
	}
}

func TestExtendedProcessCategoriesAndRisk(t *testing.T) {
	for _, test := range []struct {
		name, exe, category, severity string
		root                          bool
		score                         int
	}{
		{"shell", "/bin/sh", "shell", "high", false, 85},
		{"root shell", "/bin/bash", "root-shell", "critical", true, 95},
		{"curl", "/usr/bin/curl", "download-tool", "medium", false, 60},
		{"wget", "/usr/bin/wget", "download-tool", "medium", false, 60},
		{"root curl", "/usr/bin/curl", "download-tool", "high", true, 70},
		{"id", "/usr/bin/id", "recon-tool", "medium", false, 45},
		{"whoami", "/usr/bin/whoami", "recon-tool", "medium", false, 45},
		{"uname", "/bin/uname", "recon-tool", "medium", false, 45},
		{"hostname", "/bin/hostname", "recon-tool", "medium", false, 45},
		{"ps", "/bin/ps", "recon-tool", "medium", false, 45},
		{"nc", "/bin/nc", "connection-tool", "high", false, 70},
		{"ncat", "/bin/ncat", "connection-tool", "high", false, 70},
		{"socat", "/bin/socat", "connection-tool", "high", false, 70},
		{"temporary", "/tmp/payload", "temporary-executable", "medium", false, 65},
		{"var temporary", "/var/tmp/payload", "temporary-executable", "medium", false, 65},
		{"shared memory", "/dev/shm/payload", "temporary-executable", "medium", false, 65},
		{"memfd", "/memfd:payload (deleted)", "temporary-executable", "medium", false, 65},
		{"combined", "/tmp/curl", "temporary-executable", "high", true, 100},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := extendedEvent(test.exe)
			if test.root {
				event.Process.EUID = 0
			}
			engine := extendedEngine()
			findings := engine.Evaluate(event, lineage.New())
			if len(findings) != 1 {
				t.Fatalf("got %+v, want one observation", findings)
			}
			finding := findings[0]
			if finding.RuleID != "web-descendant-"+test.category || finding.RiskScore != test.score || finding.Severity != test.severity {
				t.Fatalf("unexpected classification: %+v", finding)
			}
			if !finding.DetectionOnly || finding.RuleVersion != "0.3.0" || finding.Confidence != .95 || len(finding.RiskFactors) > 8 {
				t.Fatalf("unexpected metadata: %+v", finding)
			}
			if finding.ID != identity.FindingID(finding.RuleID, "0.3.0", event.ID) || !reflect.DeepEqual(findings, engine.Evaluate(event, lineage.New())) {
				t.Fatal("replayed observation is not deterministic")
			}
			sum := 0
			for _, factor := range finding.RiskFactors {
				sum += factor.Score
			}
			if sum > 100 {
				sum = 100
			}
			if sum != finding.RiskScore {
				t.Fatalf("score %d disagrees with contributions %+v", finding.RiskScore, finding.RiskFactors)
			}
		})
	}
}

func TestExtendedOrdinaryProcessesDoNotAlert(t *testing.T) {
	for _, event := range []model.Event{
		extendedEvent("/usr/bin/python3", "/srv/app/worker.py"),
		extendedEvent("/usr/bin/node", "/srv/app/server.js"),
		extendedEvent("/usr/bin/php", "/srv/app/job.php"),
		extendedEvent("/usr/bin/helper"),
		extendedEvent("/usr/bin/curl-wrapper"),
		extendedEvent("/usr/bin/CURL"),
		extendedEvent("/usr/bin/ssh", "localhost"),
		extendedEvent("/opt/tmp/helper"),
		extendedEvent("/tmp-helper"),
		extendedEvent("/var/tmp-old/helper"),
		extendedEvent("/dev/shm-old/helper"),
		extendedEvent("tmp/helper"),
		extendedEvent("/tmp/../usr/bin/helper"),
		extendedEvent("/memfd:"),
	} {
		t.Run(event.Process.Exe, func(t *testing.T) {
			event.Process.CWD = "/tmp"
			event.Process.EUID = 0
			if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 0 {
				t.Fatalf("ordinary execution/root/cwd alone caused finding: %+v", findings)
			}
		})
	}
	event := extendedEvent("/usr/bin/curl")
	event.Type = "process.exit"
	if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 0 {
		t.Fatalf("exit event caused findings: %+v", findings)
	}
}

func TestExtendedExceptionsOnlyRemoveShellObservation(t *testing.T) {
	engine := extendedEngine("shop.service:sh", "shop.service:curl")
	if findings := engine.Evaluate(extendedEvent("/bin/sh"), lineage.New()); len(findings) != 0 {
		t.Fatalf("allowed shell caused findings: %+v", findings)
	}
	for _, event := range []model.Event{extendedEvent("/tmp/sh"), extendedEvent("/usr/bin/curl")} {
		findings := engine.Evaluate(event, lineage.New())
		if len(findings) != 1 || findings[0].RiskScore == 85 {
			t.Fatalf("shell exception suppressed unrelated signal: %+v", findings)
		}
		for _, factor := range findings[0].RiskFactors {
			if factor.ID == "shell_execution" {
				t.Fatalf("allowed shell contribution retained: %+v", findings)
			}
		}
	}
}

func TestExtendedSupportingMetadataAndPrivacy(t *testing.T) {
	event := extendedEvent("/usr/bin/python3", "-c", "PRIVATE_CODE https://PRIVATE_URL")
	event.Process.CWD = "/tmp"
	event.Process.EUID = 0
	finding := extendedEngine().Evaluate(event, lineage.New())[0]
	if finding.RiskScore != 85 || len(finding.RiskFactors) != 4 || finding.Severity != "high" {
		t.Fatalf("unexpected supporting factors: %+v", finding)
	}
	if strings.Contains(finding.Summary, "PRIVATE") || strings.Contains(finding.Summary, event.Process.Exe) {
		t.Fatalf("finding reason copied command contents: %+v", finding)
	}
	event.MissingFields = []string{"process.euid", "process.cwd"}
	finding = extendedEngine().Evaluate(event, lineage.New())[0]
	if finding.RiskScore != 70 || len(finding.RiskFactors) != 2 {
		t.Fatalf("unavailable supporting signals affected risk: %+v", finding)
	}
	for confidence, expected := range map[model.LineageConfidence]float64{
		model.LineageVerified: .95, model.LineageInferred: .75, model.LineageUnknown: .55,
	} {
		event.Process.LineageConfidence = confidence
		if got := extendedEngine().Evaluate(event, lineage.New())[0].Confidence; got != expected {
			t.Errorf("confidence %s = %v, want %v", confidence, got, expected)
		}
	}
}

func TestOptionsDisabledPreserveLegacyConstructors(t *testing.T) {
	for _, exe := range []string{"/bin/sh", "/bin/bash", "/usr/bin/curl", "/tmp/payload"} {
		for _, euid := range []int64{0, 1000} {
			event := extendedEvent(exe)
			event.Process.EUID = euid
			options := Options{WebExecutables: []string{"nginx"}, WebServices: []string{"shop.service"}, Shells: []string{"sh", "bash"}, AllowedPairs: []string{"shop.service:sh"}}
			legacy := NewWithServices(options.WebExecutables, options.WebServices, options.Shells, options.AllowedPairs).Evaluate(event, lineage.New())
			got := NewWithOptions(options).Evaluate(event, lineage.New())
			if !reflect.DeepEqual(got, legacy) {
				t.Fatalf("disabled options changed legacy behavior: got %+v want %+v", got, legacy)
			}
			if len(got) != 0 && (got[0].RuleVersion != "0.1.0" || got[0].RiskScore != 0 || got[0].DetectionOnly || len(got[0].RiskFactors) != 0) {
				t.Fatalf("legacy finding metadata changed: %+v", got)
			}
		}
	}
	// Executable values remain service aliases in both constructor families.
	event := extendedEvent("/bin/bash")
	event.Process.OriginService = "nginx"
	if !reflect.DeepEqual(New([]string{"nginx"}, []string{"bash"}).Evaluate(event, lineage.New()), NewWithOptions(Options{WebExecutables: []string{"nginx"}, Shells: []string{"bash"}}).Evaluate(event, lineage.New())) {
		t.Fatal("executable service alias compatibility changed")
	}
}
