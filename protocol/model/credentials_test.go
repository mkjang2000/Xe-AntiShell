package model

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func completeCredential(id uint32) *CredentialSnapshot {
	ptr := func() *uint32 { v := id; return &v }
	yes := true
	level := int32(0)
	return &CredentialSnapshot{UID: ptr(), EUID: ptr(), GID: ptr(), EGID: ptr(), SUID: ptr(), SGID: ptr(), FSUID: ptr(), FSGID: ptr(), Capabilities: &CredentialCapabilities{Effective: []string{}, Permitted: []string{}, Inheritable: []string{}}, UserNamespace: &UserNamespace{Inum: 4026531837, IsHost: &yes, Level: &level}}
}
func TestCredentialObservationRequiresCompletePairAndExactOutcome(t *testing.T) {
	zero := int64(0)
	valid := &CredentialObservation{Before: completeCredential(1000), After: completeCredential(0), TID: 14, TGID: 12, TaskStartTimeNS: 90, Evidence: CredentialEvidence, PolicyName: CredentialPolicyName, Function: "commit_creds", ReturnValue: &zero, Outcome: "applied"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CredentialObservation){func(v *CredentialObservation) { v.Before = nil }, func(v *CredentialObservation) { v.Before.EUID = nil }, func(v *CredentialObservation) { v.ReturnValue = nil }, func(v *CredentialObservation) { v.TID = 0 }, func(v *CredentialObservation) { v.TGID = 0 }, func(v *CredentialObservation) { v.TaskStartTimeNS = 0 }, func(v *CredentialObservation) { v.Evidence = "cached_exec" }, func(v *CredentialObservation) { v.PolicyName = "other" }, func(v *CredentialObservation) { v.After.UserNamespace.Inum = 0 }} {
		c := valid.Clone()
		change(c)
		if c.Validate() == nil {
			t.Fatal("incomplete or unrelated proof established applied transition")
		}
	}
	partial := valid.Clone()
	partial.Before = nil
	partial.Outcome = "unknown"
	if err := partial.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid.Clone()
	v := uint32(math.MaxUint32)
	invalid.Before.EUID = &v
	invalid.Outcome = "unknown"
	if invalid.Validate() == nil {
		t.Fatal("invalid UID accepted")
	}
}
func TestCredentialCloneAndNamespaceUnknownAreExplicit(t *testing.T) {
	s := completeCredential(0)
	s.Capabilities.Effective = []string{"CAP_SYS_ADMIN"}
	c := s.Clone()
	*s.EUID = 1000
	s.Capabilities.Effective[0] = "CAP_SETUID"
	*s.UserNamespace.IsHost = false
	if *c.EUID != 0 || c.Capabilities.Effective[0] != "CAP_SYS_ADMIN" || c.UserNamespace.Scope() != "host" {
		t.Fatal("snapshot did not own credential fields")
	}
	var n *UserNamespace
	if n.Scope() != "unknown" || (&UserNamespace{Inum: 123}).Scope() != "unknown" {
		t.Fatal("missing namespace became host/nonhost")
	}
	bad := completeCredential(0)
	bad.Capabilities.Effective = []string{"CAP_SYS_ADMIN", "CAP_SYS_ADMIN"}
	if bad.Validate() == nil {
		t.Fatal("duplicated caps accepted")
	}
	bad.Capabilities.Effective = []string{"raw command text"}
	if bad.Validate() == nil {
		t.Fatal("unbounded capability content accepted")
	}
}

func TestCredentialCloneDoesNotPromoteUnknownCapabilitySets(t *testing.T) {
	s := completeCredential(0)
	s.Capabilities.Effective = nil
	c := s.Clone()
	if c.Capabilities.Effective != nil || s.Complete() || c.Complete() {
		t.Fatal("unknown capability set became complete empty set")
	}
}

func TestCredentialTaskStartPreservesFullUint64OnTheWire(t *testing.T) {
	for _, v := range []uint64{1, 1<<53 + 1, math.MaxUint64} {
		o := CredentialObservation{TaskStartTimeNS: v}
		raw, e := json.Marshal(o)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Contains(raw, []byte(`"task_start_time_ns":"`)) {
			t.Fatal("task start lost decimal-string encoding")
		}
		var read CredentialObservation
		if e = json.Unmarshal(raw, &read); e != nil || read.TaskStartTimeNS != v {
			t.Fatalf("task start lost precision: %d %v", v, e)
		}
	}
}
