package collector

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"

	"xe-antishell/internal/model"
)

// These fields follow the pinned Tetragon v1.8.0 ProcessCredentials API.
// Pointers preserve the distinction between missing IDs and the numeric ID 0.
type tetragonCredentials struct {
	UID        *uint32                `json:"uid"`
	EUID       *uint32                `json:"euid"`
	GID        *uint32                `json:"gid"`
	EGID       *uint32                `json:"egid"`
	SUID       *uint32                `json:"suid"`
	SGID       *uint32                `json:"sgid"`
	FSUID      *uint32                `json:"fsuid"`
	FSGID      *uint32                `json:"fsgid"`
	Caps       *tetragonCapabilities  `json:"caps"`
	UserNS     *tetragonUserNamespace `json:"user_ns"`
	Securebits []string               `json:"securebits"`
}

type tetragonCapabilities struct {
	Effective   tetragonCapabilityList `json:"effective"`
	Permitted   tetragonCapabilityList `json:"permitted"`
	Inheritable tetragonCapabilityList `json:"inheritable"`
}

type tetragonNamespace struct {
	Inum   uint64 `json:"inum"`
	IsHost *bool  `json:"is_host"`
}

type tetragonNamespaces struct {
	User *tetragonNamespace `json:"user"`
}

type tetragonUserNamespace struct {
	Level *int32             `json:"level"`
	UID   *uint32            `json:"uid"`
	GID   *uint32            `json:"gid"`
	NS    *tetragonNamespace `json:"ns"`
}

type tetragonBinaryProperties struct {
	SetUID            *uint32  `json:"setuid"`
	SetGID            *uint32  `json:"setgid"`
	PrivilegesChanged []string `json:"privileges_changed"`
}

// Tetragon's bit 1 enum is spelled DAC_OVERRIDE. Internally all capabilities
// use Linux's CAP_ spelling so equality and capability-gain checks agree.
var tetragonCapabilityNames = map[string]string{
	"CAP_CHOWN": "CAP_CHOWN", "CAP_DAC_OVERRIDE": "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH": "CAP_DAC_READ_SEARCH",
	"CAP_FOWNER": "CAP_FOWNER", "CAP_FSETID": "CAP_FSETID", "CAP_KILL": "CAP_KILL", "CAP_SETGID": "CAP_SETGID",
	"CAP_SETUID": "CAP_SETUID", "CAP_SETPCAP": "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE": "CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE": "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST": "CAP_NET_BROADCAST", "CAP_NET_ADMIN": "CAP_NET_ADMIN",
	"CAP_NET_RAW": "CAP_NET_RAW", "CAP_IPC_LOCK": "CAP_IPC_LOCK", "CAP_IPC_OWNER": "CAP_IPC_OWNER",
	"CAP_SYS_MODULE": "CAP_SYS_MODULE", "CAP_SYS_RAWIO": "CAP_SYS_RAWIO", "CAP_SYS_CHROOT": "CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE": "CAP_SYS_PTRACE", "CAP_SYS_PACCT": "CAP_SYS_PACCT", "CAP_SYS_ADMIN": "CAP_SYS_ADMIN",
	"CAP_SYS_BOOT": "CAP_SYS_BOOT", "CAP_SYS_NICE": "CAP_SYS_NICE", "CAP_SYS_RESOURCE": "CAP_SYS_RESOURCE",
	"CAP_SYS_TIME": "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG": "CAP_SYS_TTY_CONFIG", "CAP_MKNOD": "CAP_MKNOD",
	"CAP_LEASE": "CAP_LEASE", "CAP_AUDIT_WRITE": "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL": "CAP_AUDIT_CONTROL",
	"CAP_SETFCAP": "CAP_SETFCAP", "CAP_MAC_OVERRIDE": "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN": "CAP_MAC_ADMIN",
	"CAP_SYSLOG": "CAP_SYSLOG", "CAP_WAKE_ALARM": "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND": "CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ": "CAP_AUDIT_READ", "CAP_PERFMON": "CAP_PERFMON", "CAP_BPF": "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE": "CAP_CHECKPOINT_RESTORE",
}

func normalizedTetragonCapabilities(source *tetragonCapabilities) (*model.CredentialCapabilities, error) {
	if source == nil {
		return nil, nil
	}
	result := &model.CredentialCapabilities{}
	for index, values := range [][]string{source.Effective, source.Permitted, source.Inheritable} {
		if len(values) > len(tetragonCapabilityNames) {
			return nil, ErrUnsupportedEvent
		}
		// A present caps object with omitted repeated fields represents empty
		// sets in proto JSON; an absent caps object remains unknown.
		set := make([]string, 0, len(values))
		for _, value := range values {
			if value == "DAC_OVERRIDE" {
				value = "CAP_DAC_OVERRIDE"
			}
			canonical, known := tetragonCapabilityNames[value]
			if !known {
				return nil, ErrUnsupportedEvent
			}
			// Names are immutable protocol constants. Do not retain separately
			// decoded copies of the same token in every process snapshot.
			set = append(set, canonical)
		}
		sort.Strings(set)
		for index := 1; index < len(set); index++ {
			if set[index] == set[index-1] {
				return nil, ErrUnsupportedEvent
			}
		}
		switch index {
		case 0:
			result.Effective = set
		case 1:
			result.Permitted = set
		case 2:
			result.Inheritable = set
		}
	}
	return result, nil
}

func normalizedTetragonCredentials(source *tetragonCredentials) (*model.CredentialSnapshot, error) {
	if source == nil {
		return nil, nil
	}
	caps, err := normalizedTetragonCapabilities(source.Caps)
	if err != nil {
		return nil, err
	}
	result := &model.CredentialSnapshot{UID: source.UID, EUID: source.EUID, GID: source.GID, EGID: source.EGID,
		SUID: source.SUID, SGID: source.SGID, FSUID: source.FSUID, FSGID: source.FSGID, Capabilities: caps}
	if ns := source.UserNS; ns != nil {
		result.UserNamespace = &model.UserNamespace{Level: ns.Level}
		if ns.NS != nil {
			result.UserNamespace.Inum, result.UserNamespace.IsHost = ns.NS.Inum, ns.NS.IsHost
			// Generic cred conversion marks the initial user namespace exactly
			// when the copier reports level0. Contradictory fields are not proof.
			if ns.Level != nil && ns.NS.IsHost != nil && (*ns.NS.IsHost != (*ns.Level == 0)) {
				return nil, ErrUnsupportedEvent
			}
		}
	}
	if err := result.Validate(); err != nil {
		return nil, ErrUnsupportedEvent
	}
	// Capability slices above are new and exclusively owned. Detach only the
	// source's mutable pointers; cloning the full result would copy them again.
	result.UID, result.EUID = copyTetragonID(result.UID), copyTetragonID(result.EUID)
	result.GID, result.EGID = copyTetragonID(result.GID), copyTetragonID(result.EGID)
	result.SUID, result.SGID = copyTetragonID(result.SUID), copyTetragonID(result.SGID)
	result.FSUID, result.FSGID = copyTetragonID(result.FSUID), copyTetragonID(result.FSGID)
	result.UserNamespace = result.UserNamespace.Clone()
	return result, nil
}

func copyTetragonID(source *uint32) *uint32 {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

// Completeness belongs only to this exclusively decoded pair. It is never
// attached to the public snapshot or carried across the queue/API boundary.
type decodedTetragonCredential struct {
	snapshot *model.CredentialSnapshot
	complete bool
}

func decodeTetragonCredentials(raw json.RawMessage) (decodedTetragonCredential, error) {
	var source *tetragonCredentials
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return decodedTetragonCredential{}, ErrUnsupportedEvent
	}
	snapshot, err := normalizedTetragonCredentials(source)
	if err != nil {
		return decodedTetragonCredential{}, err
	}
	return decodedTetragonCredential{snapshot: snapshot, complete: completeDecodedTetragonCredential(snapshot)}, nil
}

// normalizedTetragonCredentials has just validated every present value. This
// local presence check avoids repeatedly validating canonical capability sets.
func completeDecodedTetragonCredential(s *model.CredentialSnapshot) bool {
	return s != nil && s.UID != nil && s.EUID != nil && s.GID != nil && s.EGID != nil &&
		s.SUID != nil && s.SGID != nil && s.FSUID != nil && s.FSGID != nil &&
		s.Capabilities != nil && s.Capabilities.Effective != nil && s.Capabilities.Permitted != nil && s.Capabilities.Inheritable != nil &&
		s.UserNamespace != nil && s.UserNamespace.Inum != 0
}

// Exec metadata is a snapshot, never a before/current-task credential proof.
// Tetragon exec events put caps and namespace in process.cap/process.ns.user,
// while generic cred arguments carry caps and user_ns inside the argument.
func tetragonExecCredentialSnapshot(source tetragonProcess) *model.CredentialSnapshot {
	credentials := source.ProcessCredentials
	if credentials == nil && source.UID == nil && source.Capabilities == nil && (source.Namespaces == nil || source.Namespaces.User == nil) {
		return nil
	}
	copy := tetragonCredentials{EUID: source.UID}
	if credentials != nil {
		copy = *credentials
		if copy.EUID == nil {
			copy.EUID = source.UID
		}
	}
	if copy.Caps == nil {
		copy.Caps = source.Capabilities
	}
	if copy.UserNS == nil && source.Namespaces != nil && source.Namespaces.User != nil {
		copy.UserNS = &tetragonUserNamespace{NS: source.Namespaces.User}
	}
	result, err := normalizedTetragonCredentials(&copy)
	if err != nil {
		// Invalid optional privilege annotations cannot establish new facts.
		return nil
	}
	return result
}

func tetragonExecPrivileges(source *tetragonBinaryProperties) *model.ExecPrivileges {
	if source == nil || len(source.PrivilegesChanged) > 4 {
		return nil
	}
	result := &model.ExecPrivileges{SetUID: source.SetUID, SetGID: source.SetGID}
	if result.SetUID != nil && *result.SetUID == math.MaxUint32 || result.SetGID != nil && *result.SetGID == math.MaxUint32 {
		return nil
	}
	seen := map[string]bool{}
	for _, reason := range source.PrivilegesChanged {
		if reason == "PRIVILEGES_CHANGED_UNSET" {
			continue
		}
		switch reason {
		case "PRIVILEGES_RAISED_EXEC_FILE_CAP", "PRIVILEGES_RAISED_EXEC_FILE_SETUID", "PRIVILEGES_RAISED_EXEC_FILE_SETGID":
		default:
			return nil
		}
		if seen[reason] {
			return nil
		}
		seen[reason] = true
		result.Reasons = append(result.Reasons, reason)
	}
	sort.Strings(result.Reasons)
	if result.SetUID == nil && result.SetGID == nil && len(result.Reasons) == 0 {
		return nil
	}
	result.SetUID, result.SetGID = copyTetragonID(result.SetUID), copyTetragonID(result.SetGID)
	return result
}
