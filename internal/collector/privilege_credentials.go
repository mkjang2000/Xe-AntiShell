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
	Effective   []string `json:"effective"`
	Permitted   []string `json:"permitted"`
	Inheritable []string `json:"inheritable"`
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
var tetragonCapabilityNames = map[string]bool{
	"CAP_CHOWN": true, "CAP_DAC_OVERRIDE": true, "CAP_DAC_READ_SEARCH": true,
	"CAP_FOWNER": true, "CAP_FSETID": true, "CAP_KILL": true, "CAP_SETGID": true,
	"CAP_SETUID": true, "CAP_SETPCAP": true, "CAP_LINUX_IMMUTABLE": true,
	"CAP_NET_BIND_SERVICE": true, "CAP_NET_BROADCAST": true, "CAP_NET_ADMIN": true,
	"CAP_NET_RAW": true, "CAP_IPC_LOCK": true, "CAP_IPC_OWNER": true,
	"CAP_SYS_MODULE": true, "CAP_SYS_RAWIO": true, "CAP_SYS_CHROOT": true,
	"CAP_SYS_PTRACE": true, "CAP_SYS_PACCT": true, "CAP_SYS_ADMIN": true,
	"CAP_SYS_BOOT": true, "CAP_SYS_NICE": true, "CAP_SYS_RESOURCE": true,
	"CAP_SYS_TIME": true, "CAP_SYS_TTY_CONFIG": true, "CAP_MKNOD": true,
	"CAP_LEASE": true, "CAP_AUDIT_WRITE": true, "CAP_AUDIT_CONTROL": true,
	"CAP_SETFCAP": true, "CAP_MAC_OVERRIDE": true, "CAP_MAC_ADMIN": true,
	"CAP_SYSLOG": true, "CAP_WAKE_ALARM": true, "CAP_BLOCK_SUSPEND": true,
	"CAP_AUDIT_READ": true, "CAP_PERFMON": true, "CAP_BPF": true,
	"CAP_CHECKPOINT_RESTORE": true,
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
		seen := map[string]bool{}
		for _, value := range values {
			if value == "DAC_OVERRIDE" {
				value = "CAP_DAC_OVERRIDE"
			}
			if !tetragonCapabilityNames[value] || seen[value] {
				return nil, ErrUnsupportedEvent
			}
			seen[value] = true
			set = append(set, value)
		}
		sort.Strings(set)
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
	return result.Clone(), nil
}

func decodeTetragonCredentials(raw json.RawMessage) (*model.CredentialSnapshot, error) {
	var source *tetragonCredentials
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return nil, ErrUnsupportedEvent
	}
	return normalizedTetragonCredentials(source)
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
	return result.Clone()
}
