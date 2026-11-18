package model

// Unmodified validation behavior from protocol v0.3.0, retained only as a
// differential and benchmark reference for the hot-path optimization.
import (
	"errors"
	"math"
	"reflect"
	"regexp"
)

var legacyCapabilityToken = regexp.MustCompile(`^CAP_[A-Z0-9_]{1,63}$`)

// Complete describes the fixed copier's numeric, namespace and capability
// snapshot, not an independent proof of source trust.
func legacyCredentialComplete(s *CredentialSnapshot) bool {
	if s == nil || s.Capabilities == nil || s.Capabilities.Effective == nil || s.Capabilities.Permitted == nil || s.Capabilities.Inheritable == nil || s.UserNamespace == nil || s.UserNamespace.Inum == 0 {
		return false
	}
	for _, p := range []*uint32{s.UID, s.EUID, s.GID, s.EGID, s.SUID, s.SGID, s.FSUID, s.FSGID} {
		if p == nil || *p == math.MaxUint32 {
			return false
		}
	}
	return legacyCredentialValidate(s) == nil
}

func legacyCredentialValidate(s *CredentialSnapshot) error {
	if s == nil {
		return nil
	}
	for _, p := range []*uint32{s.UID, s.EUID, s.GID, s.EGID, s.SUID, s.SGID, s.FSUID, s.FSGID} {
		if p != nil && *p == math.MaxUint32 {
			return errors.New("invalid credential ID")
		}
	}
	if n := s.UserNamespace; n != nil {
		if n.Inum > math.MaxUint32 || (n.IsHost != nil && *n.IsHost && n.Inum == 0) || (n.Level != nil && (*n.Level < 0 || *n.Level > 64)) || (n.Level != nil && n.IsHost != nil && ((*n.Level == 0) != *n.IsHost)) {
			return errors.New("invalid credential user namespace")
		}
	}
	if s.Capabilities != nil {
		for _, set := range [][]string{s.Capabilities.Effective, s.Capabilities.Permitted, s.Capabilities.Inheritable} {
			if len(set) > 64 {
				return errors.New("too many credential capabilities")
			}
			seen := map[string]bool{}
			for _, name := range set {
				if !legacyCapabilityToken.MatchString(name) || seen[name] {
					return errors.New("invalid credential capability")
				}
				seen[name] = true
			}
		}
	}
	return nil
}

func legacyCredentialObservationValidate(o *CredentialObservation) error {
	if o == nil || o.TGID < 1 || o.TID < 1 || uint64(o.TGID) > math.MaxInt32 || uint64(o.TID) > math.MaxInt32 || o.TaskStartTimeNS == 0 || o.Evidence != CredentialEvidence || o.PolicyName != CredentialPolicyName || o.Function != "commit_creds" {
		return errors.New("invalid credential observation identity or evidence")
	}
	if err := legacyCredentialValidate(o.Before); err != nil {
		return err
	}
	if err := legacyCredentialValidate(o.After); err != nil {
		return err
	}
	expected := "unknown"
	if o.ReturnValue != nil {
		if *o.ReturnValue > 0 {
			return errors.New("invalid credential return")
		}
		if *o.ReturnValue < 0 {
			expected = "failed"
		} else if legacyCredentialComplete(o.Before) && legacyCredentialComplete(o.After) {
			expected = "applied"
		}
	}
	if o.Outcome != expected {
		return errors.New("credential outcome does not match paired evidence")
	}
	return nil
}

// Unknown snapshots must not collapse into a fabricated unchanged observation.
// Source adapters normalize capability ordering before comparing snapshots.
func legacyCredentialEqual(s, other *CredentialSnapshot) bool {
	return legacyCredentialComplete(s) && legacyCredentialComplete(other) && reflect.DeepEqual(s, other)
}
