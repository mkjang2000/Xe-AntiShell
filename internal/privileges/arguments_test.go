package privileges

import "testing"

func TestEventArgumentsOnlyAllowUnfilteredJSONAndPrivacyExclusions(t *testing.T) {
	for _, args := range [][]string{
		{"getevents", "-o", "json"},
		{"--server-address", "unix:///run/tetragon/tetragon.sock", "getevents", "-o", "json", "--exclude-fields", "process.arguments,process.environment_variables,parent.arguments,parent.environment_variables,ancestors.arguments,ancestors.environment_variables"},
		{"--server-address=unix:///run/tetragon/tetragon.sock", "--timeout=5s", "--retries=0", "getevents", "--output=json", "-F=process.arguments,parent.arguments", "--exclude-fields", "ancestors.environment_variables"},
	} {
		if !EventArgumentsUsable(args) {
			t.Fatalf("reviewed subscription rejected: %q", args)
		}
	}
	base := []string{"--server-address", "unix:///run/tetragon/tetragon.sock", "getevents", "-o", "json"}
	for _, extra := range [][]string{
		{"--process", ".*"}, {"--process=.*"}, {"--processes", "sh"}, {"--process-credentials"},
		{"--event-types", "PROCESS_EXEC"}, {"--event-types=PROCESS_KPROBE"}, {"-e", "PROCESS_EXEC"}, {"-ePROCESS_EXEC"},
		{"--include-fields", "process"}, {"-f", "process.uid"}, {"-fprocess.uid"},
		{"--exclude-fields", "process.cred"}, {"--exclude-fields", "process"}, {"--exclude-fields", "process_kprobe"},
		{"--exclude-fields", "process.arguments,process.cred"}, {"-Fprocess.cred"}, {"-F", "process.cred"},
		{"--exclude-fields", "process.arguments,"}, {"--exclude-fields", ",process.arguments"},
		{"--exclude-fields", `"process.arguments,process.cred"`}, {"--exclude-fields", `"process.arguments"`},
		{"--exclude-fields", "process.arguments, process.cred"}, {"--exclude-fields", "process.arguments\nprocess.cred"},
		{"--exclude-fields", "process.arguments.*"}, {"--exclude-fields", "process.credentials"},
		{"--exclude-fields", "process.tid"}, {"--exclude-fields", "process_kprobe.args"}, {"--exclude-fields", "process.creds.capabilities"},
		{"--namespace", "default"}, {"--namespaces=default"}, {"-n", "default"}, {"--namespace-regex", ".*"},
		{"--host"}, {"--host=false"}, {"--containers", ".*"}, {"--pod", ".*"}, {"--pods", ".*"},
		{"--policy-names", "xeas-credential-change-v1"}, {"--cel-expression", "true"}, {"--allowlist", "{}"}, {"--denylist", "{}"},
		{"--tty-encode", "/tmp/data"}, {"-t", "/tmp/data"}, {"--output", "compact"}, {"-ojson"},
		{"--unknown-future-filter", "value"}, {"--"}, {"extra-positional"}, {"getevents"},
		{"--server-address", "unix:///run/other.sock"}, {"--server-address="},
		{"--timeout", "0"}, {"--timeout", "-1s"}, {"--timeout", "1h"}, {"--retries", "-1"}, {"--retries", "11"}, {"--retries", "00"},
	} {
		args := append(append([]string{}, base...), extra...)
		if EventArgumentsUsable(args) {
			t.Fatalf("source narrowing or ambiguous arguments accepted: %q", extra)
		}
	}
	for _, args := range [][]string{
		nil, {"getevents"}, {"-o", "json"}, {"getevents", "-o"},
		{"--server-address", "unix:///run/../tmp/t.sock", "getevents", "-o", "json"},
		{"--server-address", "127.0.0.1:54321", "getevents", "-o", "json"},
		{"--server-address", "unix:///run//t.sock", "getevents", "-o", "json"},
	} {
		if EventArgumentsUsable(args) {
			t.Fatalf("incomplete/unsafe arguments accepted: %q", args)
		}
	}
}
