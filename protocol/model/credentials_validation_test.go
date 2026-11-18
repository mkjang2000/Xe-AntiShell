package model

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func credentialErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func assertCredentialReference(t *testing.T, s *CredentialSnapshot) {
	t.Helper()
	before, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := credentialErrorText(s.Validate()), credentialErrorText(legacyCredentialValidate(s)); got != want {
		t.Fatalf("Validate changed: got=%q want=%q snapshot=%s", got, want, before)
	}
	if got, want := s.Complete(), legacyCredentialComplete(s); got != want {
		t.Fatalf("Complete changed: got=%v want=%v snapshot=%s", got, want, before)
	}
	if got, want := s.Equal(s.Clone()), legacyCredentialEqual(s, s.Clone()); got != want {
		t.Fatalf("Equal changed: got=%v want=%v snapshot=%s", got, want, before)
	}
	after, err := json.Marshal(s)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("validation changed caller-owned values or wire encoding")
	}
}

func TestCapabilityTokenByteEquivalentToLegacyRegexp(t *testing.T) {
	tokens := []string{"", "CAP_", "CAP_A", "CAP_0", "CAP__", "CAP_FUTURE_UNKNOWN", "CAP_DAC_OVERRIDE", "DAC_OVERRIDE", "cap_SYS_ADMIN", "CAP_a", "CAP_A\n", "CAP_A\r", "CAP_A\x00", "CAP_É", "CAP_Ａ", " CAP_A", "CAP_A ", "CAP_" + strings.Repeat("A", 63), "CAP_" + strings.Repeat("A", 64)}
	for value := 0; value < 256; value++ {
		tokens = append(tokens, "CAP_"+string([]byte{byte(value)}), "CAP_A"+string([]byte{byte(value)})+"0")
	}
	for _, token := range tokens {
		if got, want := validCapabilityToken(token), legacyCapabilityToken.MatchString(token); got != want {
			t.Fatalf("token %q: got=%v want=%v", token, got, want)
		}
	}
}

func TestCapabilitySetsPreserveUnsortedFutureAndDuplicateSemantics(t *testing.T) {
	for _, set := range [][]string{nil, {}, {"CAP_A"}, {"CAP_FUTURE_X", "CAP_0", "CAP__"}, {"CAP_A", "CAP_B", "CAP_C"}, {"CAP_B", "CAP_A", "CAP_C"}, {"CAP_A", "CAP_C", "CAP_B", "CAP_A"}, {"CAP_C", "CAP_A", "CAP_B", "CAP_C"}, {"CAP_A", "CAP_A"}, {"CAP_C", "CAP_B", "CAP_A", "CAP_A"}, {"CAP_A", "CAP_bad"}} {
		s := completeCredential(0)
		s.Capabilities.Effective = set
		assertCredentialReference(t, s)
	}
	for _, length := range []int{63, 64, 65} {
		set := make([]string, length)
		for i := range set {
			set[i] = "CAP_" + strings.Repeat("A", i/26+1) + string(rune('A'+i%26))
		}
		sort.Strings(set)
		for _, reverse := range []bool{false, true} {
			s := completeCredential(0)
			s.Capabilities.Permitted = append([]string{}, set...)
			if reverse {
				sort.Sort(sort.Reverse(sort.StringSlice(s.Capabilities.Permitted)))
			}
			assertCredentialReference(t, s)
		}
	}
}

func generatedCredential(r *rand.Rand) *CredentialSnapshot {
	if r.Intn(12) == 0 {
		return nil
	}
	s := completeCredential(uint32(r.Intn(3)))
	for _, target := range []**uint32{&s.UID, &s.EUID, &s.GID, &s.EGID, &s.SUID, &s.SGID, &s.FSUID, &s.FSGID} {
		switch r.Intn(18) {
		case 0:
			*target = nil
		case 1:
			value := uint32(math.MaxUint32)
			*target = &value
		}
	}
	if r.Intn(8) == 0 {
		s.UserNamespace = nil
	} else {
		s.UserNamespace.Inum = []uint64{0, 1, 4026531837, math.MaxUint32, math.MaxUint32 + 1}[r.Intn(5)]
		switch r.Intn(3) {
		case 0:
			s.UserNamespace.IsHost = nil
		case 1:
			*s.UserNamespace.IsHost = false
		}
		switch r.Intn(6) {
		case 0:
			s.UserNamespace.Level = nil
		default:
			value := []int32{-1, 0, 1, 64, 65}[r.Intn(5)]
			s.UserNamespace.Level = &value
		}
	}
	if r.Intn(8) == 0 {
		s.Capabilities = nil
		return s
	}
	for _, target := range []*[]string{&s.Capabilities.Effective, &s.Capabilities.Permitted, &s.Capabilities.Inheritable} {
		if r.Intn(7) == 0 {
			*target = nil
			continue
		}
		set := make([]string, r.Intn(67))
		for index := range set {
			switch r.Intn(18) {
			case 0:
				set[index] = "CAP_bad"
			case 1:
				set[index] = "CAP_" + strings.Repeat("X", 64)
			case 2:
				set[index] = "CAP_A\x00"
			default:
				set[index] = "CAP_FUTURE_" + string(rune('A'+r.Intn(26))) + string(rune('A'+r.Intn(26)))
			}
		}
		if r.Intn(2) == 0 {
			sort.Strings(set)
		}
		*target = set
	}
	return s
}
func TestCredentialValidationDifferentialProperty(t *testing.T) {
	r := rand.New(rand.NewSource(20261118))
	for i := 0; i < 4000; i++ {
		snapshot := generatedCredential(r)
		assertCredentialReference(t, snapshot)
		other := generatedCredential(r)
		if got, want := snapshot.Equal(other), legacyCredentialEqual(snapshot, other); got != want {
			t.Fatalf("cross-snapshot equality changed at case %d", i)
		}
		observation := &CredentialObservation{Before: snapshot, After: other, TGID: 12, TID: 14, TaskStartTimeNS: 90, Evidence: CredentialEvidence, PolicyName: CredentialPolicyName, Function: "commit_creds"}
		switch r.Intn(4) {
		case 0:
		case 1:
			value := int64(-1)
			observation.ReturnValue = &value
		case 2:
			value := int64(0)
			observation.ReturnValue = &value
		case 3:
			value := int64(1)
			observation.ReturnValue = &value
		}
		observation.Outcome = []string{"unknown", "failed", "applied", "invalid"}[r.Intn(4)]
		if r.Intn(15) == 0 {
			observation.TID = 0
		}
		if got, want := credentialErrorText(observation.Validate()), credentialErrorText(legacyCredentialObservationValidate(observation)); got != want {
			t.Fatalf("observation error changed: got=%q want=%q", got, want)
		}
	}
}

func TestCredentialValidationNeverReusesPastResult(t *testing.T) {
	s := completeCredential(0)
	s.Capabilities.Effective = []string{"CAP_FUTURE_A", "CAP_FUTURE_B"}
	copy := s.Clone()
	if s.Validate() != nil || !s.Complete() || !s.Equal(copy) {
		t.Fatal("valid baseline rejected")
	}
	*s.EUID = math.MaxUint32
	if s.Validate() == nil || s.Complete() || s.Equal(s) {
		t.Fatal("ID mutation reused a valid result or pointer identity")
	}
	*s.EUID = 0
	s.Capabilities.Effective[0] = "CAP_invalid"
	if s.Validate() == nil || s.Complete() || s.Equal(copy) {
		t.Fatal("capability mutation reused a valid result")
	}
	s.Capabilities.Effective[0] = "CAP_FUTURE_A"
	s.Capabilities.Effective = append(s.Capabilities.Effective, "CAP_FUTURE_A")
	if s.Validate() == nil || s.Complete() {
		t.Fatal("appended duplicate reused a valid result")
	}
	s.Capabilities.Effective = nil
	if s.Validate() != nil || s.Complete() || s.Equal(s) {
		t.Fatal("unknown set became known empty or unchanged")
	}
	if !copy.Complete() || !reflect.DeepEqual(copy.Capabilities.Effective, []string{"CAP_FUTURE_A", "CAP_FUTURE_B"}) {
		t.Fatal("validation or later mutations changed the clone")
	}
	s = copy.Clone()
	*s.UserNamespace.Level = 1
	if s.Validate() == nil || s.Complete() {
		t.Fatal("namespace mutation reused a valid result")
	}
	s = copy.Clone()
	s.UserNamespace.IsHost = nil
	if s.Validate() != nil || !s.Complete() || s.UserNamespace.Scope() != "unknown" {
		t.Fatal("unknown scope changed snapshot completeness")
	}
	zero := int64(0)
	o := &CredentialObservation{Before: copy.Clone(), After: copy.Clone(), TGID: 12, TID: 14, TaskStartTimeNS: 90, Evidence: CredentialEvidence, PolicyName: CredentialPolicyName, Function: "commit_creds", ReturnValue: &zero, Outcome: "applied"}
	if o.Validate() != nil {
		t.Fatal("valid observation rejected")
	}
	o.Before.EUID = nil
	if o.Validate() == nil {
		t.Fatal("observation reused old completeness")
	}
	o.Outcome = "unknown"
	if o.Validate() != nil {
		t.Fatal("partial unknown observation was rejected")
	}
}

func FuzzCapabilityTokenEquivalentToLegacy(f *testing.F) {
	for _, seed := range []string{"CAP_A", "CAP_0", "CAP_FUTURE_UNKNOWN", "CAP_", "CAP_A\x00", "CAP_A\n", "CAP_É", "CAP_" + strings.Repeat("A", 63)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > 256 {
			t.Skip()
		}
		if got, want := validCapabilityToken(token), legacyCapabilityToken.MatchString(token); got != want {
			t.Fatalf("token mismatch %q", token)
		}
	})
}
func FuzzCredentialCapabilitiesEquivalentToLegacy(f *testing.F) {
	for _, seed := range []string{"", "CAP_A", "CAP_C\x00CAP_A\x00CAP_B", "CAP_A\x00CAP_C\x00CAP_B\x00CAP_A", "CAP_FUTURE_X\x00CAP_A", "CAP_bad"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > 4096 {
			t.Skip()
		}
		set := strings.Split(encoded, "\x00")
		if len(set) > 66 {
			t.Skip()
		}
		s := completeCredential(0)
		s.Capabilities.Effective = set
		assertCredentialReference(t, s)
	})
}
