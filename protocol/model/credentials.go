package model

import (
	"errors"
	"math"
	"reflect"
)

// UserNamespace identifies the user namespace of a credential, not complete
// container isolation or unrestricted host authority. Missing data is unknown.
type UserNamespace struct {
	Inum   uint64 `json:"inum" yaml:"inum"`
	IsHost *bool  `json:"is_host,omitempty" yaml:"is_host,omitempty"`
	Level  *int32 `json:"level,omitempty" yaml:"level,omitempty"`
}

// ExecPrivileges contains source exec properties, not a before/after transition.
type ExecPrivileges struct {
	SetUID  *uint32  `json:"setuid,omitempty" yaml:"setuid,omitempty"`
	SetGID  *uint32  `json:"setgid,omitempty" yaml:"setgid,omitempty"`
	Reasons []string `json:"reasons,omitempty" yaml:"reasons,omitempty"`
}

// A present empty capability list means a known empty set. A missing object
// means no reliable snapshot; comparisons must not turn unknown into empty.
type CredentialCapabilities struct {
	Effective   []string `json:"effective" yaml:"effective"`
	Permitted   []string `json:"permitted" yaml:"permitted"`
	Inheritable []string `json:"inheritable" yaml:"inheritable"`
}

type CredentialSnapshot struct {
	UID           *uint32                 `json:"uid,omitempty" yaml:"uid,omitempty"`
	EUID          *uint32                 `json:"euid,omitempty" yaml:"euid,omitempty"`
	GID           *uint32                 `json:"gid,omitempty" yaml:"gid,omitempty"`
	EGID          *uint32                 `json:"egid,omitempty" yaml:"egid,omitempty"`
	SUID          *uint32                 `json:"suid,omitempty" yaml:"suid,omitempty"`
	SGID          *uint32                 `json:"sgid,omitempty" yaml:"sgid,omitempty"`
	FSUID         *uint32                 `json:"fsuid,omitempty" yaml:"fsuid,omitempty"`
	FSGID         *uint32                 `json:"fsgid,omitempty" yaml:"fsgid,omitempty"`
	Capabilities  *CredentialCapabilities `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	UserNamespace *UserNamespace          `json:"user_namespace,omitempty" yaml:"user_namespace,omitempty"`
}

// CredentialObservation is a paired fixed-kernel-hook observation. Before is
// read from current_task.cred at entry, never inferred from cached exec state.
// Return0 plus complete same-hook evidence can establish application. Partial
// evidence remains unknown and must not establish a confirmed escalation.
type CredentialObservation struct {
	Before          *CredentialSnapshot `json:"before,omitempty" yaml:"before,omitempty"`
	After           *CredentialSnapshot `json:"after,omitempty" yaml:"after,omitempty"`
	TGID            int                 `json:"tgid" yaml:"tgid"`
	TID             int                 `json:"tid" yaml:"tid"`
	TaskStartTimeNS uint64              `json:"task_start_time_ns,string" yaml:"task_start_time_ns"`
	Evidence        string              `json:"evidence" yaml:"evidence"`
	PolicyName      string              `json:"policy_name" yaml:"policy_name"`
	Function        string              `json:"function" yaml:"function"`
	ReturnValue     *int64              `json:"return_value,omitempty" yaml:"return_value,omitempty"`
	Outcome         string              `json:"outcome" yaml:"outcome"`
}

// NamespaceScope distinguishes only the user namespace. Host here does not
// mean unconstrained privileges or absence of container isolation.
func (n *UserNamespace) Scope() string {
	if n == nil || n.Inum == 0 || n.IsHost == nil {
		return "unknown"
	}
	if *n.IsHost {
		return "host"
	}
	return "non_host"
}

func (n *UserNamespace) Clone() *UserNamespace {
	if n == nil {
		return nil
	}
	c := *n
	if n.IsHost != nil {
		v := *n.IsHost
		c.IsHost = &v
	}
	if n.Level != nil {
		v := *n.Level
		c.Level = &v
	}
	return &c
}
func (e *ExecPrivileges) Clone() *ExecPrivileges {
	if e == nil {
		return nil
	}
	c := *e
	if e.SetUID != nil {
		v := *e.SetUID
		c.SetUID = &v
	}
	if e.SetGID != nil {
		v := *e.SetGID
		c.SetGID = &v
	}
	c.Reasons = append([]string(nil), e.Reasons...)
	return &c
}
func (s *CredentialSnapshot) Clone() *CredentialSnapshot {
	if s == nil {
		return nil
	}
	c := *s
	copyID := func(p *uint32) *uint32 {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	c.UID, c.EUID, c.GID, c.EGID = copyID(s.UID), copyID(s.EUID), copyID(s.GID), copyID(s.EGID)
	c.SUID, c.SGID, c.FSUID, c.FSGID = copyID(s.SUID), copyID(s.SGID), copyID(s.FSUID), copyID(s.FSGID)
	c.UserNamespace = s.UserNamespace.Clone()
	if s.Capabilities != nil {
		v := *s.Capabilities
		if v.Effective != nil {
			v.Effective = append([]string{}, v.Effective...)
		}
		if v.Permitted != nil {
			v.Permitted = append([]string{}, v.Permitted...)
		}
		if v.Inheritable != nil {
			v.Inheritable = append([]string{}, v.Inheritable...)
		}
		c.Capabilities = &v
	}
	return &c
}
func (o *CredentialObservation) Clone() *CredentialObservation {
	if o == nil {
		return nil
	}
	c := *o
	c.Before = o.Before.Clone()
	c.After = o.After.Clone()
	if o.ReturnValue != nil {
		v := *o.ReturnValue
		c.ReturnValue = &v
	}
	return &c
}

const CredentialPolicyName = "xeas-credential-change-v1"
const CredentialEvidence = "tetragon_commit_creds_pair"

// validCapabilityToken is byte-equivalent to ^CAP_[A-Z0-9_]{1,63}$.
// Future well-formed CAP_* names remain valid; this is not a Linux-name enum.
func validCapabilityToken(name string) bool {
	if len(name) < 5 || len(name) > 67 || name[:4] != "CAP_" {
		return false
	}
	for index := 4; index < len(name); index++ {
		value := name[index]
		if (value < 'A' || value > 'Z') && (value < '0' || value > '9') && value != '_' {
			return false
		}
	}
	return true
}

func validateCredentialCapabilities(set []string) error {
	if len(set) > 64 {
		return errors.New("too many credential capabilities")
	}
	var seen map[string]struct{}
	previous := ""
	for index, name := range set {
		if !validCapabilityToken(name) {
			return errors.New("invalid credential capability")
		}
		if index > 0 {
			if name == previous {
				return errors.New("invalid credential capability")
			}
			if seen == nil && name < previous {
				// The validated prefix is sorted and unique. Only unordered
				// public inputs need a map; never sort caller-owned evidence.
				seen = make(map[string]struct{}, len(set))
				for _, earlier := range set[:index] {
					seen[earlier] = struct{}{}
				}
			}
		}
		if seen != nil {
			if _, duplicate := seen[name]; duplicate {
				return errors.New("invalid credential capability")
			}
			seen[name] = struct{}{}
		}
		previous = name
	}
	return nil
}

// checkCredentialSnapshot derives completeness while validating current values.
// Its result is call-local: public snapshots are mutable and carry no cache.
func checkCredentialSnapshot(s *CredentialSnapshot) (bool, error) {
	if s == nil {
		return false, nil
	}
	complete := true
	for _, p := range []*uint32{s.UID, s.EUID, s.GID, s.EGID, s.SUID, s.SGID, s.FSUID, s.FSGID} {
		if p == nil {
			complete = false
		} else if *p == math.MaxUint32 {
			return false, errors.New("invalid credential ID")
		}
	}
	if n := s.UserNamespace; n != nil {
		if n.Inum > math.MaxUint32 || (n.IsHost != nil && *n.IsHost && n.Inum == 0) || (n.Level != nil && (*n.Level < 0 || *n.Level > 64)) || (n.Level != nil && n.IsHost != nil && ((*n.Level == 0) != *n.IsHost)) {
			return false, errors.New("invalid credential user namespace")
		}
		if n.Inum == 0 {
			complete = false
		}
	} else {
		complete = false
	}
	if s.Capabilities != nil {
		for _, set := range [][]string{s.Capabilities.Effective, s.Capabilities.Permitted, s.Capabilities.Inheritable} {
			if set == nil {
				complete = false
			}
			if err := validateCredentialCapabilities(set); err != nil {
				return false, err
			}
		}
	} else {
		complete = false
	}
	return complete, nil
}

// Complete describes the fixed copier's numeric, namespace and capability
// snapshot, not an independent proof of source trust.
func (s *CredentialSnapshot) Complete() bool {
	// Keep partial observations cheap: presence alone can establish that a
	// snapshot is incomplete. Full values still receive a fresh validation.
	if s == nil || s.Capabilities == nil || s.Capabilities.Effective == nil || s.Capabilities.Permitted == nil || s.Capabilities.Inheritable == nil || s.UserNamespace == nil || s.UserNamespace.Inum == 0 {
		return false
	}
	for _, p := range []*uint32{s.UID, s.EUID, s.GID, s.EGID, s.SUID, s.SGID, s.FSUID, s.FSGID} {
		if p == nil || *p == math.MaxUint32 {
			return false
		}
	}
	complete, err := checkCredentialSnapshot(s)
	return err == nil && complete
}

func (s *CredentialSnapshot) Validate() error {
	_, err := checkCredentialSnapshot(s)
	return err
}

func (o *CredentialObservation) Validate() error {
	if o == nil || o.TGID < 1 || o.TID < 1 || uint64(o.TGID) > math.MaxInt32 || uint64(o.TID) > math.MaxInt32 || o.TaskStartTimeNS == 0 || o.Evidence != CredentialEvidence || o.PolicyName != CredentialPolicyName || o.Function != "commit_creds" {
		return errors.New("invalid credential observation identity or evidence")
	}
	beforeComplete, err := checkCredentialSnapshot(o.Before)
	if err != nil {
		return err
	}
	afterComplete, err := checkCredentialSnapshot(o.After)
	if err != nil {
		return err
	}
	expected := "unknown"
	if o.ReturnValue != nil {
		if *o.ReturnValue > 0 {
			return errors.New("invalid credential return")
		}
		if *o.ReturnValue < 0 {
			expected = "failed"
		} else if beforeComplete && afterComplete {
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
func (s *CredentialSnapshot) Equal(other *CredentialSnapshot) bool {
	return s.Complete() && other.Complete() && reflect.DeepEqual(s, other)
}
