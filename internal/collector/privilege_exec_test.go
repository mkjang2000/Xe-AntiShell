package collector

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTetragonExecParsesSeparatePrivilegeSnapshot(t *testing.T) {
	fixture := observationFixture("unused")
	probe := fixture["process_tracepoint"].(map[string]any)
	process := probe["process"].(map[string]any)
	delete(fixture, "process_tracepoint")
	fixture["process_exec"] = map[string]any{"process": process}
	process["tid"], process["uid"] = 42, 0
	credentials := credentialSnapshotFixture(0)
	delete(credentials, "caps")
	delete(credentials, "user_ns")
	process["process_credentials"] = credentials
	process["cap"] = map[string]any{"effective": []string{"DAC_OVERRIDE", "CAP_SETUID"}, "permitted": []string{"CAP_SETUID"}}
	process["ns"] = map[string]any{"user": map[string]any{"inum": 4026531837, "is_host": true}, "net": map[string]any{"inum": 12345}}
	process["binary_properties"] = map[string]any{"setuid": 0, "privileges_changed": []string{"PRIVILEGES_RAISED_EXEC_FILE_SETUID"}, "file": map[string]any{"path": observationPrivateFixture}}
	event, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := event.Process.Credentials
	if event.Type != "process.exec" || event.Credential != nil || event.Process.TID != 42 || snapshot == nil || !snapshot.Complete() || snapshot.EUID == nil || *snapshot.EUID != 0 || *snapshot.UID != 1000 || snapshot.UserNamespace.Scope() != "host" {
		t.Fatalf("incorrect exec snapshot: %+v", snapshot)
	}
	if strings.Join(snapshot.Capabilities.Effective, ",") != "CAP_DAC_OVERRIDE,CAP_SETUID" || snapshot.Capabilities.Inheritable == nil || len(snapshot.Capabilities.Inheritable) != 0 {
		t.Fatal("exec top-level capability metadata lost")
	}
	if event.Process.ExecPrivileges == nil || event.Process.ExecPrivileges.SetUID == nil || *event.Process.ExecPrivileges.SetUID != 0 || strings.Join(event.Process.ExecPrivileges.Reasons, ",") != "PRIVILEGES_RAISED_EXEC_FILE_SETUID" {
		t.Fatal("zero setuid wrapper or exec reason lost")
	}
	// Existing raw-event retention is handled by the normalizer's configured
	// privacy boundary. None of the new typed proof fields contains argv.
	encoded, _ := json.Marshal(struct {
		Credentials any
		Privileges  any
		Argv        []string
	}{snapshot, event.Process.ExecPrivileges, event.Process.Argv})
	if strings.Contains(string(encoded), observationPrivateFixture) || len(event.Process.Argv) != 1 || event.Process.Argv[0] != process["binary"] {
		t.Fatal("flattened arguments leaked into typed exec privilege fields")
	}
}

func TestTetragonExecMissingMetadataDoesNotInventCredentials(t *testing.T) {
	process := tetragonProcess{PID: 42, Binary: "/usr/bin/id"}
	result := tetragonToProcess(process, time.Now())
	if result.Credentials != nil || result.ExecPrivileges != nil || result.TID != 0 {
		t.Fatal("missing source became privilege evidence")
	}
	zero := uint32(0)
	process.UID = &zero
	result = tetragonToProcess(process, time.Now())
	if result.Credentials == nil || result.Credentials.EUID == nil || *result.Credentials.EUID != 0 || result.Credentials.UID != nil || result.Credentials.UserNamespace != nil || result.Credentials.Complete() {
		t.Fatal("top-level EUID fabricated real UID or namespace")
	}
	process.ProcessCredentials = &tetragonCredentials{UID: &zero, EUID: &zero}
	process.BinaryProperties = &tetragonBinaryProperties{PrivilegesChanged: []string{observationPrivateFixture}}
	result = tetragonToProcess(process, time.Now())
	if result.Credentials == nil || result.Credentials.Complete() || result.ExecPrivileges != nil {
		t.Fatal("incomplete credentials or arbitrary reason became complete evidence")
	}
}

func TestTetragonExecInvalidPrivilegeAnnotationsAreNotTrusted(t *testing.T) {
	for _, source := range []*tetragonBinaryProperties{
		{PrivilegesChanged: []string{"PRIVILEGES_RAISED_EXEC_FILE_SETUID", "PRIVILEGES_RAISED_EXEC_FILE_SETUID"}},
		{PrivilegesChanged: []string{"PRIVILEGES_CHANGED_UNSET"}},
		{PrivilegesChanged: []string{"PRIVILEGES_RAISED_EXEC_FILE_SETUID", "unknown"}},
	} {
		if tetragonExecPrivileges(source) != nil {
			t.Fatal("invalid, duplicate or unset exec reason became evidence")
		}
	}
	if len(tetragonCapabilityNames) != 41 {
		t.Fatal("pinned capability enum coverage changed")
	}
}
