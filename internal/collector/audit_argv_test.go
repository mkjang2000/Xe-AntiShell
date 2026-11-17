package collector

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/detection"
	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

func assembleAuditArguments(t *testing.T, options AuditAssemblerOptions, records []string, finish bool) model.Event {
	t.Helper()
	assembler := NewAuditAssembler(options)
	now := time.Unix(1700000001, 0).UTC()
	lines := []string{`type=SYSCALL msg=audit(1700000000.100:99): pid=400 ppid=1 uid=1000 euid=1000 exe="/usr/bin/python3"`}
	for _, fields := range records {
		lines = append(lines, "type=EXECVE msg=audit(1700000000.100:99): "+fields)
	}
	if finish {
		lines = append(lines, "type=EOE msg=audit(1700000000.100:99):")
	}
	var events []model.Event
	for _, line := range lines {
		produced, err := assembler.Feed(line, now)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, produced...)
	}
	if !finish {
		events = append(events, assembler.FlushAll(now.Add(time.Second))...)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want one", len(events))
	}
	return events[0]
}

func auditArgvUnavailable(event model.Event) bool {
	for _, field := range event.MissingFields {
		if field == "process.argv_exact" {
			return true
		}
	}
	return false
}

func TestAuditArgumentsRetainExactMultiRecordOrder(t *testing.T) {
	for _, test := range []struct {
		name    string
		records []string
		want    []string
	}{
		{"single", []string{`argc=3 a0="python3" a1="-c" a2="print(1)"`}, []string{"python3", "-c", "print(1)"}},
		{"continuation without repeated argc", []string{`argc=3 a0="python3" a1="-c"`, `a2="print(1)"`}, []string{"python3", "-c", "print(1)"}},
		{"consistent repeated argc", []string{`argc=3 a0="python3"`, `argc=3 a1="-c" a2="print(1)"`}, []string{"python3", "-c", "print(1)"}},
		{"empty arguments", []string{`argc=4 a0="python3" a1=""`, `a2="-c" a3=""`}, []string{"python3", "", "-c", ""}},
		{"hex flag and code", []string{`argc=3 a0="python3" a1=2D63 a2=7072696E74283129`}, []string{"python3", "-c", "print(1)"}},
		{"quoted hex looking text", []string{`argc=2 a0="python3" a1="1234"`}, []string{"python3", "1234"}},
		{"zero count", []string{`argc=0`}, []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := assembleAuditArguments(t, AuditAssemblerOptions{}, test.records, true)
			if !reflect.DeepEqual(event.Process.Argv, test.want) || auditArgvUnavailable(event) || event.Completeness != model.CompletenessComplete {
				t.Fatalf("exact arguments not preserved: %+v", event)
			}
		})
	}
}

func TestAuditArgumentsRejectUncertainVectorsWithoutCompressingPositions(t *testing.T) {
	for _, test := range []struct {
		name    string
		records []string
	}{
		{"interior hole", []string{`argc=4 a0="python3" a2="-c" a3="print(1)"`}},
		{"missing argv zero", []string{`argc=4 a1="worker.py" a2="-c" a3="print(1)"`}},
		{"missing last argument", []string{`argc=4 a0="python3" a1="-c" a2="print(1)"`}},
		{"missing argc", []string{`a0="python3" a1="-c" a2="print(1)"`}},
		{"conflicting argc", []string{`argc=4 a0="python3"`, `argc=3 a1="-c" a2="print(1)"`}},
		{"duplicate argc in record", []string{`argc=4 argc=3 a0="python3" a1="-c" a2="print(1)"`}},
		{"duplicate argument", []string{`argc=3 a0="python3" a1="worker.py"`, `a1="-c" a2="print(1)"`}},
		{"duplicate argument in record", []string{`argc=3 a0="python3" a1="worker.py" a1="-c" a2="print(1)"`}},
		{"fragmented argument", []string{`argc=4 a0="python3" a1_len=18 a1[0]=776F726B65722E7079`, `a1[1]=2E62616B a2="-c" a3="print(1)"`}},
		{"fragment with matching plain indices", []string{`argc=3 a0="python3" a1="-c" a2="print(1)" a2[0]=7072696E74283129`}},
		{"unclosed quote", []string{`argc=3 a0="python3" a1="-c" a2="print(1)`}},
		{"malformed token", []string{`argc=3 a0="python3" a1="-c" UNKNOWN a2="print(1)"`}},
		{"empty field name", []string{`argc=3 a0="python3" a1="-c" =UNKNOWN a2="print(1)"`}},
		{"escaped quote semantics", []string{`argc=3 a0="python3" a1="-c" a2="print(\"value\")"`}},
		{"invalid hex", []string{`argc=3 a0="python3" a1="-c" a2=PRIVATE_SECRET`}},
		{"odd hex length", []string{`argc=3 a0="python3" a1="-c" a2=123`}},
		{"invalid utf8", []string{`argc=3 a0="python3" a1="-c" a2=FF`}},
		{"embedded nul", []string{`argc=3 a0="python3" a1="-c" a2=610062`}},
		{"negative argc", []string{`argc=-1 a0="python3" a1="-c" a2="print(1)"`}},
		{"huge argc", []string{`argc=18446744073709551615 a0="python3" a1="-c" a2="print(1)"`}},
		{"bounded argc", []string{fmt.Sprintf(`argc=%d a0="python3" a1="-c" a2="print(1)"`, maxAuditArguments+1)}},
		{"huge index", []string{`argc=3 a0="python3" a1="-c" a18446744073709551615="print(1)"`}},
		{"noncanonical index", []string{`argc=3 a0="python3" a01="-c" a2="print(1)"`}},
		{"out of range index", []string{`argc=3 a0="python3" a1="-c" a3="print(1)"`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := assembleAuditArguments(t, AuditAssemblerOptions{}, test.records, true)
			if event.Process.Argv != nil || !auditArgvUnavailable(event) || event.Completeness != model.CompletenessPartial {
				t.Fatalf("uncertain arguments were marked exact or compressed: %+v", event)
			}
			if event.Process.Exe != "/usr/bin/python3" {
				t.Fatalf("argv uncertainty changed executable evidence: %+v", event.Process)
			}
			assertNoAuditInlineFinding(t, event)
			// Metadata must identify unavailable fields without retaining the
			// unsupported argument or its encoded representation.
			if strings.Contains(strings.Join(event.MissingFields, " "), "PRIVATE") {
				t.Fatal("argument contents leaked into field metadata")
			}
		})
	}
}

func TestAuditIncompleteGroupsDiscloseUnavailableExactArguments(t *testing.T) {
	for _, test := range []struct {
		name    string
		options AuditAssemblerOptions
		finish  bool
	}{
		{"missing EOE", AuditAssemblerOptions{}, false},
		{"record limit", AuditAssemblerOptions{MaxRecords: 2}, true},
		{"byte limit", AuditAssemblerOptions{MaxBytes: 200}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := assembleAuditArguments(t, test.options, []string{`argc=3 a0="python3" a1="-c" a2="print(1)"`}, test.finish)
			if !auditArgvUnavailable(event) || event.Completeness != model.CompletenessPartial {
				t.Fatalf("incomplete group retained exactness: %+v", event)
			}
			assertNoAuditInlineFinding(t, event)
		})
	}
}

func assertNoAuditInlineFinding(t *testing.T, event model.Event) {
	t.Helper()
	event.Process.OriginService = "example-web.service"
	engine := detection.NewWithOptions(detection.Options{
		WebServices: []string{"example-web.service"}, Shells: []string{"sh"}, ExtendedProcessRules: true,
	})
	if findings := engine.Evaluate(event, lineage.New()); len(findings) != 0 {
		t.Fatalf("uncertain audit argv caused inline observation: %+v", findings)
	}
}
