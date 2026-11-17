package detection

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

func TestTemporaryScriptInvocationsUseExactOperandBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, exe, cwd, location, option string
		args                             []string
	}{
		{"python", "python3.12", "", "temporary", "", []string{"-I", "/tmp/PRIVATE_SCRIPT"}},
		{"node", "node22", "", "temporary", "", []string{"--no-warnings", "/var/tmp/PRIVATE_SCRIPT"}},
		{"php-explicit", "php8.3", "", "temporary", "-f", []string{"-n", "-f", "/dev/shm/PRIVATE_SCRIPT"}},
		{"perl", "perl5.36", "", "temporary", "", []string{"-w", "/tmp/PRIVATE_SCRIPT"}},
		{"ruby", "ruby3.2", "", "temporary", "", []string{"--disable-gems", "/tmp/PRIVATE_SCRIPT"}},
		{"relative", "python3", "/tmp/work", "temporary", "", []string{"PRIVATE_SCRIPT"}},
		{"separator", "python3", "", "temporary", "", []string{"--", "/tmp/PRIVATE_SCRIPT"}},
		{"memory", "python3", "", "memory", "", []string{"/memfd:PRIVATE_SCRIPT"}},
		{"proc-fd", "python3", "", "fd", "", []string{"/proc/self/fd/3"}},
		{"thread-fd", "node", "", "fd", "", []string{"/proc/thread-self/fd/5"}},
		{"dev-fd", "ruby", "", "fd", "", []string{"/dev/fd/4"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := extendedEvent("/usr/bin/"+test.exe, test.args...)
			event.Process.CWD = test.cwd
			event.RawJSON = json.RawMessage(`{"private":"PRIVATE_CODE"}`)
			SummarizeExecution(&event)
			if event.Execution == nil || event.Execution.Mode != "script" || event.Execution.Evidence != "exact_argv" || event.Execution.ScriptLocation != test.location || event.Execution.Option != test.option {
				t.Fatalf("script invocation facts missing: %#v", event.Execution)
			}
			findings := extendedEngine().Evaluate(event, lineage.New())
			if len(findings) != 1 || findings[0].RuleID != "web-descendant-temporary-script" || !findings[0].DetectionOnly {
				t.Fatalf("temporary script observation missing: %#v", findings)
			}
			wantScore := 60
			if test.cwd != "" {
				wantScore += 5
			}
			if findings[0].RiskScore != wantScore || strings.Contains(findings[0].Summary, "PRIVATE") {
				t.Fatalf("incorrect score or private finding metadata: %#v", findings)
			}
			assertExecutionPrivacy(t, event)
		})
	}
}

func TestScriptClassificationRejectsOrdinaryOrAmbiguousInvocations(t *testing.T) {
	for _, test := range []struct {
		exe, cwd string
		args     []string
		missing  []string
	}{
		{"python3", "/tmp", []string{"/srv/app/worker.py", "-c", "PRIVATE_CODE"}, nil},
		{"node", "/tmp", []string{"/srv/app/server.js", "--eval", "PRIVATE_CODE"}, nil},
		{"php", "", []string{"-f", "/srv/app/job.php", "-r", "PRIVATE_CODE"}, nil},
		{"python3", "/tmp", []string{"-m", "worker", "-c", "PRIVATE_CODE"}, nil},
		{"python3", "", []string{"worker.py"}, nil},
		{"python3", "/tmp", []string{"worker.py"}, []string{"process.cwd"}},
		{"python3", "/tmp", []string{"../srv/worker.py"}, nil},
		{"python3", "", []string{"/tmp/../srv/worker.py"}, nil},
		{"python3", "", []string{"/var/tmp-old/worker.py"}, nil},
		{"python3", "", []string{"/proc/self/fd/not-a-descriptor"}, nil},
		{"python3", "", []string{"/proc/other/fd/3"}, nil},
		{"python3", "", []string{"/memfd:"}, nil},
		{"python3", "", []string{"--unknown", "/tmp/worker.py"}, nil},
		{"node", "", []string{"--check", "/tmp/worker.js"}, nil},
		{"php", "", []string{"-l", "/tmp/worker.php"}, nil},
		{"perl", "", []string{"-c", "/tmp/worker.pl"}, nil},
		{"ruby", "", []string{"-c", "/tmp/worker.rb"}, nil},
		{"python3", "/tmp", []string{"-"}, nil},
		{"python-helper", "", []string{"/tmp/worker.py"}, nil},
		{"PRIVATE_RENAMED_RUNTIME", "", []string{"/tmp/worker.py"}, nil},
	} {
		t.Run(test.exe+"/"+strings.Join(test.args, " "), func(t *testing.T) {
			event := extendedEvent("/usr/bin/"+test.exe, test.args...)
			event.Process.CWD, event.MissingFields = test.cwd, test.missing
			SummarizeExecution(&event)
			if event.Execution != nil || len(extendedEngine().Evaluate(event, lineage.New())) != 0 {
				t.Fatalf("ordinary or ambiguous script became evidence: %#v", event.Execution)
			}
		})
	}
}

func TestSummarizeExecutionKeepsProofAndRemovesAllRuntimeCode(t *testing.T) {
	for _, test := range []struct{ runtime, option string }{{"python3", "-c"}, {"node", "-e"}, {"node", "--eval"}, {"node", "-p"}, {"node", "--print"}, {"php", "-r"}, {"perl", "-e"}, {"perl", "-E"}, {"ruby", "-e"}} {
		t.Run(test.runtime+test.option, func(t *testing.T) {
			event := extendedEvent("/usr/bin/"+test.runtime, test.option, "PRIVATE_CODE", "PRIVATE_ARGUMENT")
			event.RawJSON = json.RawMessage(`{"raw":"PRIVATE_CODE"}`)
			event.Ancestors = []model.Process{{Argv: []string{"python3", "-c", "PRIVATE_ANCESTOR_CODE"}}}
			SummarizeExecution(&event)
			if event.Execution == nil || event.Execution.Mode != "inline" || event.Execution.Option != test.option {
				t.Fatalf("inline proof was lost while removing code: %#v", event.Execution)
			}
			before, _ := json.Marshal(event)
			SummarizeExecution(&event)
			after, _ := json.Marshal(event)
			if !bytes.Equal(before, after) {
				t.Fatal("repeated privacy normalization changed the evidence")
			}
			findings := extendedEngine().Evaluate(event, lineage.New())
			if len(findings) != 1 || findings[0].RuleID != "web-descendant-inline-interpreter" || findings[0].RiskScore != 70 || !findings[0].DetectionOnly {
				t.Fatalf("redacting argv removed valid inline evidence: %#v", findings)
			}
			assertExecutionPrivacy(t, event)
		})
	}
	for _, args := range [][]string{{"--unknown", "-c", "PRIVATE_CODE"}, {"-cPRIVATE_CODE"}, {"worker.py", "-c", "PRIVATE_CODE"}, {"-c", "PRIVATE\x00CODE"}, {"-c", string([]byte{0xff})}} {
		event := extendedEvent("/usr/bin/python3", args...)
		event.RawJSON = json.RawMessage(`{"raw":"PRIVATE_CODE"}`)
		SummarizeExecution(&event)
		if event.Execution != nil {
			t.Fatalf("ambiguous arguments produced exact proof: %#v", event.Execution)
		}
		assertExecutionPrivacy(t, event)
	}
}

func TestTetragonSignalsRequireExactReviewedPolicyTuple(t *testing.T) {
	for _, test := range []struct{ policy, runtime, option string }{
		{"python-c", "python", "-c"}, {"node-e", "node", "-e"}, {"node-eval", "node", "--eval"}, {"node-p", "node", "-p"}, {"node-print", "node", "--print"},
		{"php-r", "php", "-r"}, {"perl-e", "perl", "-e"}, {"perl-capital-e", "perl", "-E"}, {"ruby-e", "ruby", "-e"},
	} {
		t.Run(test.policy, func(t *testing.T) {
			event := extendedEvent("/opt/runtime/renamed")
			event.Type, event.Source, event.Process.Argv = "process.exec_observation", "tetragon", nil
			event.Execution = &model.ExecutionObservation{Runtime: test.runtime, Mode: "inline", Evidence: "tetragon_policy", Option: test.option, PolicyName: "xeas-exec-" + test.policy + "-v1"}
			event.MissingFields = []string{"process.argv_exact"}
			findings := extendedEngine().Evaluate(event, lineage.New())
			if len(findings) != 1 || findings[0].RuleID != "web-descendant-inline-interpreter" || !findings[0].DetectionOnly {
				t.Fatalf("reviewed code-free policy evidence was rejected: %#v", findings)
			}
			if !reflect.DeepEqual(findings, extendedEngine().Evaluate(event, lineage.New())) {
				t.Fatal("policy signal replay changed finding identity")
			}
			if findings := NewWithOptions(Options{WebServices: []string{"shop.service"}}).Evaluate(event, lineage.New()); len(findings) != 0 {
				t.Fatal("signal enabled a disabled extended profile")
			}
		})
	}
	for _, mutate := range []func(*model.Event){
		func(event *model.Event) { event.Execution = nil },
		func(event *model.Event) { event.Type = "process.exec" },
		func(event *model.Event) { event.Source = "audit" },
		func(event *model.Event) { event.Execution.Evidence = "exact_argv" },
		func(event *model.Event) { event.Execution.PolicyName = "unknown-policy" },
		func(event *model.Event) { event.Execution.PolicyName = "xeas-exec-node-e-v1" },
		func(event *model.Event) { event.Execution.Runtime = "node" },
		func(event *model.Event) { event.Execution.Option = "--unknown" },
		func(event *model.Event) { event.Execution.Mode = "script" },
		func(event *model.Event) { event.Execution.ScriptLocation = "temporary" },
		func(event *model.Event) { event.Process.OriginService = "other.service" },
	} {
		event := extendedEvent("/usr/bin/python3", "-c", "PRIVATE_CODE")
		event.Type, event.Source = "process.exec_observation", "tetragon"
		event.Execution = &model.ExecutionObservation{Runtime: "python", Mode: "inline", Evidence: "tetragon_policy", Option: "-c", PolicyName: "xeas-exec-python-c-v1"}
		mutate(&event)
		if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 0 {
			t.Fatalf("untrusted policy tuple or origin caused a finding: %#v", event)
		}
	}
}

func TestTypedExactEvidenceRejectsIncompleteSourceFields(t *testing.T) {
	event := extendedEvent("/usr/bin/python3", "-c", "PRIVATE_CODE")
	SummarizeExecution(&event)
	for _, field := range []string{"process", "process.argv", "process.argv_exact", "process.argv[2]", "process.argv.2"} {
		for _, truncated := range []bool{false, true} {
			copy := event
			if truncated {
				copy.TruncatedFields = []string{field}
			} else {
				copy.MissingFields = []string{field}
			}
			if ValidExecutionEvidence(copy) {
				t.Fatalf("preexisting exact proof hid unavailable source arguments: field=%s truncated=%t", field, truncated)
			}
		}
	}
	for _, field := range []string{"process.argv_exact", "process.argv[2]", "process.argv.2"} {
		copy := event
		copy.RedactedFields = []string{field}
		if ValidExecutionEvidence(copy) {
			t.Fatalf("unexpected source redaction was treated as whole-argv privacy removal: %s", field)
		}
	}
}

func TestExecutionPrivacyDoesNotInferExactTetragonOrSpoofedRuntime(t *testing.T) {
	event := extendedEvent("/usr/bin/python3", "-c", "PRIVATE_FLATTENED_CODE")
	event.Source = "tetragon"
	SummarizeExecution(&event)
	if event.Execution != nil || len(extendedEngine().Evaluate(event, lineage.New())) != 0 {
		t.Fatal("Tetragon flattened arguments were treated as exact argv")
	}
	assertExecutionPrivacy(t, event)
	event = extendedEvent("/opt/runtime/renamed", "-c", "PRIVATE_CODE")
	event.Process.Argv[0] = "python3"
	if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 0 {
		t.Fatal("attacker-controlled argv[0] established a runtime identity")
	}
	// Shell exceptions do not exempt independent non-shell execution evidence.
	event = extendedEvent("/usr/bin/python3", "/tmp/script.py")
	SummarizeExecution(&event)
	if findings := extendedEngine("shop.service:python3").Evaluate(event, lineage.New()); len(findings) != 1 || !findings[0].DetectionOnly {
		t.Fatalf("shell-only exception removed script observation: %#v", findings)
	}
}

func TestSummarizeExecutionDoesNotPromoteUnavailableArguments(t *testing.T) {
	for _, field := range []string{"process", "process.exe", "process.argv", "process.argv_exact", "process.argv[2]", "audit.records", "audit.EOE"} {
		for _, status := range []string{"missing", "truncated", "redacted"} {
			t.Run(status+field, func(t *testing.T) {
				event := extendedEvent("/usr/bin/python3", "-c", "PRIVATE_CODE")
				event.RawJSON = json.RawMessage(`{"raw":"PRIVATE_CODE"}`)
				switch status {
				case "missing":
					event.MissingFields = []string{field}
				case "truncated":
					event.TruncatedFields = []string{field}
				case "redacted":
					event.RedactedFields = []string{field}
				}
				SummarizeExecution(&event)
				if event.Execution != nil || len(extendedEngine().Evaluate(event, lineage.New())) != 0 {
					t.Fatalf("unavailable arguments became exact evidence: %#v", event.Execution)
				}
				assertExecutionPrivacy(t, event)
			})
		}
	}
	// Root and temporary CWD are supporting factors for a script observation.
	event := extendedEvent("/usr/bin/python3", "/tmp/worker.py")
	event.Process.EUID, event.Process.CWD = 0, "/tmp"
	event.MissingFields = []string{"process.euid", "process.cwd"}
	SummarizeExecution(&event)
	findings := extendedEngine().Evaluate(event, lineage.New())
	if len(findings) != 1 || findings[0].RiskScore != 60 || findings[0].Severity != "medium" {
		t.Fatalf("missing supporting context added risk: %#v", findings)
	}
}

func TestValidExecutionEvidenceRequiresExplicitProofAndSurvivesPrivacy(t *testing.T) {
	event := extendedEvent("/usr/bin/python3", "-c", "PRIVATE_CODE")
	if ValidExecutionEvidence(event) {
		t.Fatal("validation inferred a proof from raw argv")
	}
	SummarizeExecution(&event)
	if !ValidExecutionEvidence(event) || fieldAvailable(event, "process.argv") {
		t.Fatal("intentional argv removal invalidated the derived proof")
	}
	for _, mutate := range []func(*model.Event){
		func(event *model.Event) { event.Source = "tetragon" },
		func(event *model.Event) { event.Execution.Runtime = "ruby" },
		func(event *model.Event) { event.Execution.PolicyName = "unexpected" },
		func(event *model.Event) { event.MissingFields = []string{"audit.EOE"} },
		func(event *model.Event) { event.MissingFields = []string{"process.exe"} },
	} {
		copy := event
		proof := *event.Execution
		copy.Execution = &proof
		mutate(&copy)
		if ValidExecutionEvidence(copy) {
			t.Fatalf("invalid proof passed public validation: %#v", copy.Execution)
		}
	}
}

func TestSummarizeExecutionPreservesLegacyShellAndRawOptInScope(t *testing.T) {
	event := extendedEvent("/bin/sh", "-c", "LEGACY_SHELL_ARGUMENT")
	event.RawJSON = json.RawMessage(`{"legacy":"opt-in raw event"}`)
	event.Ancestors = []model.Process{{Argv: []string{"legacy-parent-argument"}}}
	argv, raw := append([]string(nil), event.Process.Argv...), append([]byte(nil), event.RawJSON...)
	SummarizeExecution(&event)
	if event.Execution != nil || !reflect.DeepEqual(event.Process.Argv, argv) || !bytes.Equal(event.RawJSON, raw) {
		t.Fatal("new runtime privacy changed the legacy shell/raw collection policy")
	}
	if len(event.Ancestors[0].Argv) != 0 {
		t.Fatal("ancestor argv was not removed at the queue boundary")
	}
}

func assertExecutionPrivacy(t *testing.T, event model.Event) {
	t.Helper()
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Process.Argv) != 0 || len(event.RawJSON) != 0 || bytes.Contains(encoded, []byte("PRIVATE")) {
		t.Fatalf("runtime code or arguments survived privacy normalization: %s", encoded)
	}
	for _, ancestor := range event.Ancestors {
		if len(ancestor.Argv) != 0 {
			t.Fatal("ancestor arguments survived queue-boundary privacy normalization")
		}
	}
}
