package detection

import (
	"testing"
	"time"

	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

func TestExtendedInlineInterpreterOptions(t *testing.T) {
	for _, test := range []struct {
		exe  string
		args []string
		want bool
	}{
		{"python", []string{"-c", "print(1)"}, true},
		{"python2.7", []string{"-c", "print(1)"}, true},
		{"python3.12", []string{"-I", "-W", "ignore", "-c", "print(1)"}, true},
		{"python3", []string{"-Xdev", "-c", "print(1)"}, true},
		{"node", []string{"-e", "1"}, true},
		{"nodejs", []string{"--eval", "1"}, true},
		{"node22", []string{"--input-type=module", "--eval", "1"}, true},
		{"perl", []string{"-e", "1"}, true},
		{"perl5.36", []string{"-w", "-e", "1"}, true},
		{"php", []string{"-r", "echo 1;"}, true},
		{"php8.3", []string{"-d", "display_errors=0", "-r", "echo 1;"}, true},
		{"ruby", []string{"-e", "1"}, true},
		{"ruby3.2", []string{"--disable-gems", "-e", "1"}, true},
		{"python3", []string{"worker.py", "-c", "print(1)"}, false},
		{"python3", []string{"-m", "worker", "-c", "print(1)"}, false},
		{"python3", []string{"--", "-c", "print(1)"}, false},
		{"python3", []string{"-c"}, false},
		{"python3", []string{"-c", "  "}, false},
		{"python3", []string{"-cprint(1)"}, false},
		{"python3", []string{"--unsupported", "-c", "print(1)"}, false},
		{"node", []string{"worker.js", "--eval", "1"}, false},
		{"node", []string{"--", "-e", "1"}, false},
		{"node", []string{"--require", "-e", "module"}, false},
		{"node", []string{"--eval=1"}, false},
		{"php", []string{"-f", "worker.php", "-r", "1"}, false},
		{"perl", []string{"worker.pl", "-e", "1"}, false},
		{"ruby", []string{"worker.rb", "-e", "1"}, false},
		{"python-helper", []string{"-c", "1"}, false},
		{"python3.12-worker", []string{"-c", "1"}, false},
		{"python3.", []string{"-c", "1"}, false},
		{"node_modules", []string{"-e", "1"}, false},
		{"php-fpm8.3", []string{"-r", "1"}, false},
	} {
		t.Run(test.exe+"/"+test.args[0], func(t *testing.T) {
			event := extendedEvent("/usr/bin/"+test.exe, test.args...)
			findings := extendedEngine().Evaluate(event, lineage.New())
			if (len(findings) == 1) != test.want {
				t.Fatalf("args %+v got %+v, want match=%t", test.args, findings, test.want)
			}
			if len(findings) == 1 && (findings[0].RuleID != "web-descendant-inline-interpreter" || findings[0].RiskScore != 70) {
				t.Fatalf("unexpected inline observation: %+v", findings)
			}
		})
	}
}

func TestExtendedInlineRejectsUnavailableArgv(t *testing.T) {
	for _, field := range []string{"process", "process.argv", "process.argv_exact", "process.argv[2]", "process.argv.2", "audit.records", "audit.EOE"} {
		for _, status := range []string{"missing", "redacted", "truncated"} {
			t.Run(status+"/"+field, func(t *testing.T) {
				event := extendedEvent("/usr/bin/python3", "-c", "print(1)")
				switch status {
				case "missing":
					event.MissingFields = []string{field}
				case "redacted":
					event.RedactedFields = []string{field}
				case "truncated":
					event.TruncatedFields = []string{field}
				}
				if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 0 {
					t.Fatalf("unavailable argument boundaries caused finding: %+v", findings)
				}
			})
		}
	}
	event := extendedEvent("/usr/bin/python3", "-c", "print(1)")
	event.MissingFields = []string{"ancestors"}
	event.TruncatedFields = []string{"raw_json"}
	if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 1 {
		t.Fatalf("unrelated telemetry loss suppressed exact inline arguments: %+v", findings)
	}
	event = extendedEvent("/usr/bin/python3", "-c", "print(1)")
	event.Source = "tetragon"
	if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 0 {
		t.Fatalf("flattened Tetragon arguments caused inline finding: %+v", findings)
	}
	// Missing argv removes only the inline signal, preserving executable evidence.
	event.Process.Exe = "/tmp/python3"
	findings := extendedEngine().Evaluate(event, lineage.New())
	if len(findings) != 1 || findings[0].RuleID != "web-descendant-temporary-executable" || findings[0].RiskScore != 65 {
		t.Fatalf("argv loss suppressed independent temporary execution: %+v", findings)
	}
	for _, exe := range []string{"/usr/bin/curl", "/usr/bin/id", "/usr/bin/nc", "/tmp/payload"} {
		event := extendedEvent(exe)
		event.Process.Argv = nil
		if findings := extendedEngine().Evaluate(event, lineage.New()); len(findings) != 1 {
			t.Fatalf("missing argv suppressed executable classification %s: %+v", exe, findings)
		}
	}
}

func TestExtendedWebOriginAndProcessIdentity(t *testing.T) {
	for _, origin := range []string{"/usr/sbin/nginx", "/usr/sbin/sshd", "/usr/bin/deploy"} {
		t.Run(origin, func(t *testing.T) {
			graph := lineage.New()
			now := time.Now().UTC()
			parent := model.Event{BootID: "boot", EventTime: now, IngestTime: now, Process: model.Process{PID: 100, PPID: 1, ExecID: "parent", Exe: origin}}
			graph.Observe(&parent)
			worker := model.Event{BootID: "boot", EventTime: now.Add(time.Second), IngestTime: now.Add(time.Second), Process: model.Process{PID: 101, PPID: 100, ExecID: "worker", Exe: "/usr/bin/helper"}}
			graph.Observe(&worker)
			event := extendedEvent("/usr/bin/curl")
			event.Process.PID = 102
			event.Process.PPID = 101
			event.Process.Key = ""
			event.Process.OriginService = ""
			event.EventTime = now.Add(2 * time.Second)
			event.IngestTime = event.EventTime
			// Before observation the current PPID owner provides the same scope.
			before := extendedEngine().Evaluate(event, graph)
			graph.Observe(&event)
			after := extendedEngine().Evaluate(event, graph)
			want := origin == "/usr/sbin/nginx"
			if (len(before) == 1) != want || (len(after) == 1) != want {
				t.Fatalf("origin %s: before=%+v after=%+v want=%t", origin, before, after, want)
			}
		})
	}
	graph := lineage.New()
	parent := model.Event{BootID: "boot", EventTime: time.Now().UTC(), Process: model.Process{PID: 100, PPID: 1, ExecID: "new-web", Exe: "/usr/sbin/nginx"}}
	graph.Observe(&parent)
	event := extendedEvent("/usr/bin/curl")
	event.Process.OriginService = ""
	event.Process.ParentKey = "old-parent-with-reused-pid"
	if findings := extendedEngine().Evaluate(event, graph); len(findings) != 0 {
		t.Fatalf("explicit absent parent replaced with reused PID web owner: %+v", findings)
	}
	event.Process.ParentKey = ""
	event.Process.PPID = 999
	if findings := extendedEngine().Evaluate(event, graph); len(findings) != 0 {
		t.Fatalf("missing lineage invented web origin: %+v", findings)
	}
}
