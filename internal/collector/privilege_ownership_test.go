package collector

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestTetragonCredentialConversionOwnsMutablePointersAndSets(t *testing.T) {
	zero, level, host := uint32(0), int32(0), true
	set := []string{"CAP_SETUID", "DAC_OVERRIDE"}
	source := &tetragonCredentials{UID: &zero, EUID: &zero, GID: &zero, EGID: &zero, SUID: &zero, SGID: &zero, FSUID: &zero, FSGID: &zero,
		Caps: &tetragonCapabilities{Effective: set, Permitted: set}, UserNS: &tetragonUserNamespace{Level: &level, NS: &tetragonNamespace{Inum: 1, IsHost: &host}}}
	first, err := normalizedTetragonCredentials(source)
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizedTetragonCredentials(source)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set, []string{"CAP_SETUID", "DAC_OVERRIDE"}) {
		t.Fatal("normalization sorted or rewrote caller-owned input")
	}
	zero, level, host, set[0] = 1000, 1, false, "CAP_KILL"
	if *first.UID != 0 || *first.EUID != 0 || *first.UserNamespace.Level != 0 || !*first.UserNamespace.IsHost || first.Capabilities.Effective[1] != "CAP_SETUID" {
		t.Fatal("source mutation changed normalized credential evidence")
	}
	*first.UID, *first.UserNamespace.Level, *first.UserNamespace.IsHost = 2000, 2, false
	first.Capabilities.Effective[0] = "CAP_KILL"
	if *first.EUID != 0 || *second.UID != 0 || *second.UserNamespace.Level != 0 || !*second.UserNamespace.IsHost || second.Capabilities.Effective[0] != "CAP_DAC_OVERRIDE" || first.Capabilities.Permitted[0] != "CAP_DAC_OVERRIDE" || set[0] != "CAP_KILL" {
		t.Fatal("normalized snapshots, fields or input share mutable storage")
	}
}

func TestTetragonExecPropertiesOwnSourceIDsAndReasons(t *testing.T) {
	zero := uint32(0)
	source := &tetragonBinaryProperties{SetUID: &zero, SetGID: &zero, PrivilegesChanged: []string{"PRIVILEGES_RAISED_EXEC_FILE_SETUID"}}
	first, second := tetragonExecPrivileges(source), tetragonExecPrivileges(source)
	zero = 1000
	source.PrivilegesChanged[0] = "PRIVILEGES_RAISED_EXEC_FILE_CAP"
	*first.SetUID = 2000
	first.Reasons[0] = "PRIVILEGES_RAISED_EXEC_FILE_SETGID"
	if *first.SetGID != 0 || *second.SetUID != 0 || *second.SetGID != 0 || second.Reasons[0] != "PRIVILEGES_RAISED_EXEC_FILE_SETUID" || zero != 1000 {
		t.Fatal("exec properties share mutable source or sibling storage")
	}
}

func TestFreshDecodedCredentialCompletenessMatchesPublicContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"complete", func(map[string]any) {}},
		{"missing uid", func(s map[string]any) { delete(s, "uid") }},
		{"missing euid", func(s map[string]any) { delete(s, "euid") }},
		{"missing suid", func(s map[string]any) { delete(s, "suid") }},
		{"missing namespace", func(s map[string]any) { delete(s, "user_ns") }},
		{"missing scope", func(s map[string]any) { delete(s["user_ns"].(map[string]any)["ns"].(map[string]any), "is_host") }},
		{"missing caps", func(s map[string]any) { delete(s, "caps") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := credentialSnapshotFixture(0)
			test.change(source)
			raw, _ := json.Marshal(source)
			decoded, err := decodeTetragonCredentials(raw)
			if err != nil || decoded.complete != decoded.snapshot.Complete() {
				t.Fatalf("private completeness diverged from current public input contract: %v", err)
			}
		})
	}
	decoded, err := decodeTetragonCredentials(json.RawMessage("null"))
	if err != nil || decoded.snapshot != nil || decoded.complete {
		t.Fatal("null credential acquired complete evidence")
	}
}

func TestTetragonCanonicalCapabilitiesRetainPinnedEnumBoundary(t *testing.T) {
	for _, values := range [][]string{{"CAP_FUTURE_EXTENSION"}, {"CAP_SETUID", "CAP_SETUID"}, {"DAC_OVERRIDE", "CAP_DAC_OVERRIDE"}, {"CAP_setuid"}, {"CAP_SETUID\x00"}} {
		if _, err := normalizedTetragonCapabilities(&tetragonCapabilities{Effective: values}); !errors.Is(err, ErrUnsupportedEvent) {
			t.Fatal("unknown, invalid or duplicate Tetragon enum was accepted")
		}
	}
	value, err := normalizedTetragonCapabilities(&tetragonCapabilities{Effective: []string{"CAP_SETUID", "DAC_OVERRIDE"}})
	if err != nil || !reflect.DeepEqual(value.Effective, []string{"CAP_DAC_OVERRIDE", "CAP_SETUID"}) || value.Permitted == nil || value.Inheritable == nil {
		t.Fatal("canonical order, alias or known-empty representation changed")
	}
}
