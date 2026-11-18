package detection

import "xe-antishell/internal/model"

func (e *Engine) evaluateCredentials(event model.Event, lineage AncestorProvider, r ruleDecision) []model.Finding {
	c := event.Credential
	if event.Source != "tetragon" || event.Type != "process.credential_change" || event.BootID == "" ||
		event.Process.ExecID == "" || event.Process.StartTime.IsZero() || event.EventTime.IsZero() || c == nil || c.Validate() != nil || c.Outcome != "applied" ||
		c.ReturnValue == nil || *c.ReturnValue != 0 || c.TGID != event.Process.PID || c.TID < 1 || c.TaskStartTimeNS == 0 ||
		(event.Process.TID != 0 && event.Process.TID != c.TID) || !privilegeFieldAvailable(event, "credential") ||
		!privilegeFieldAvailable(event, "process.pid") || !privilegeFieldAvailable(event, "process.exec_id") ||
		!privilegeFieldAvailable(event, "process.start_time") || !privilegeFieldAvailable(event, "event_time") {
		return nil
	}
	before, after := c.Before, c.After
	if before == nil || after == nil || before.EUID == nil || after.EUID == nil {
		return nil
	}
	origin, web := e.privilegeWebOrigin(event, lineage)
	if !web {
		origin = event.Process.OriginService
	}
	factors := []model.RiskFactor{}
	rule, summary := "", ""
	if *before.EUID != 0 && *after.EUID == 0 {
		sameNamespace := sameCredentialNamespace(before, after)
		restorable := isRootID(before.UID) || isRootID(before.SUID)
		switch {
		case sameNamespace && restorable:
			rule = rulePrivilegeRootRestored
			summary = "보유한 root 자격으로 EUID 0 복귀 관측. 승인된 작업인지 확인."
			factors = append(factors, model.RiskFactor{ID: "root_identity_restored", Score: 40})
		case sameNamespace && before.UserNamespace.Scope() == "host" && before.UID != nil && before.SUID != nil && !restorable:
			rule = rulePrivilegeHostRootGain
			summary = "동일 초기 user namespace에서 EUID 비0→0 변경 적용 관측. 승인된 권한 상승인지 확인."
			factors = append(factors, model.RiskFactor{ID: "initial_namespace_root_gain", Score: 75})
		default:
			rule = rulePrivilegeRootIdentityChange
			summary = "EUID 비0→0 변경 적용 관측. user namespace와 승인된 작업 범위를 확인."
			factors = append(factors, model.RiskFactor{ID: "root_identity_change", Score: 50})
		}
	}
	if rule != "" && !r.allows(rule) {
		rule = ""
		factors = nil
	}
	gain, activation, dangerous := capabilityIncrease(before, after)
	if rule == "" {
		switch {
		case gain && r.allows(rulePrivilegeCapabilityGain):
			rule = rulePrivilegeCapabilityGain
			summary = "프로세스 Capability 권한집합 증가 관측. user namespace와 승인된 작업인지 확인."
			factors = append(factors, model.RiskFactor{ID: "capability_gain", Score: 45})
		case activation && r.allows(rulePrivilegeCapabilityActivated):
			rule = rulePrivilegeCapabilityActivated
			summary = "기존 permitted 범위의 Capability 활성화 관측. 승인된 작업인지 확인."
			factors = append(factors, model.RiskFactor{ID: "permitted_capability_activation", Score: 25})
		default:
			return nil
		}
	} else if gain {
		factors = append(factors, model.RiskFactor{ID: "additional_capability_gain", Score: 15})
	}
	if gain && dangerous {
		contribution := 10
		if sameCredentialNamespace(before, after) && after.UserNamespace.Scope() == "host" {
			contribution = 30
		}
		factors = append(factors, model.RiskFactor{ID: "sensitive_capability_gain", Score: contribution})
	}
	if web {
		factors = append(factors, model.RiskFactor{ID: "web_origin", Score: 15})
	}
	if privilegeFieldAvailable(event, "process.exe") && temporaryPath(event.Process.Exe, false) {
		factors = append(factors, model.RiskFactor{ID: "temporary_executable", Score: 10})
	}
	return privilegeFinding(event, rule, summary, factors, origin, .95)
}

// The adapter's advisory marker describes scope, not loss of the paired IDs,
// capabilities or return. A contradictory marker on known-host data fails closed.
func unresolvedCredentialNamespaceScope(c *model.CredentialObservation) bool {
	return c != nil && c.Before != nil && c.After != nil &&
		(c.Before.UserNamespace.Scope() == "unknown" || c.After.UserNamespace.Scope() == "unknown")
}

func sameCredentialNamespace(before, after *model.CredentialSnapshot) bool {
	return before.UserNamespace != nil && after.UserNamespace != nil && before.UserNamespace.Inum > 0 &&
		before.UserNamespace.Inum == after.UserNamespace.Inum && before.UserNamespace.Scope() == after.UserNamespace.Scope()
}

func isRootID(id *uint32) bool { return id != nil && *id == 0 }

// A newly effective capability that was already permitted is activation, not
// acquisition of a new permitted authority. Unknown snapshots are never empty.
func capabilityIncrease(before, after *model.CredentialSnapshot) (gain, activation, dangerous bool) {
	if before.Capabilities == nil || after.Capabilities == nil {
		return
	}
	b, a := before.Capabilities, after.Capabilities
	if b.Effective == nil || b.Permitted == nil || a.Effective == nil || a.Permitted == nil {
		return
	}
	oldEffective, oldPermitted := capabilitySet(b.Effective), capabilitySet(b.Permitted)
	for _, capability := range a.Permitted {
		if _, had := oldPermitted[capability]; !had {
			gain = true
			dangerous = dangerous || sensitiveCapability(capability)
		}
	}
	for _, capability := range a.Effective {
		if _, had := oldEffective[capability]; had {
			continue
		}
		if _, permitted := oldPermitted[capability]; permitted {
			activation = true
		} else {
			gain = true
			dangerous = dangerous || sensitiveCapability(capability)
		}
	}
	return
}
func capabilitySet(capabilities []string) map[string]struct{} {
	out := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		out[capability] = struct{}{}
	}
	return out
}
func sensitiveCapability(capability string) bool {
	switch capability {
	case "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO", "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETPCAP", "CAP_SYS_BOOT", "CAP_BPF", "CAP_PERFMON", "CAP_NET_ADMIN":
		return true
	default:
		return false
	}
}
