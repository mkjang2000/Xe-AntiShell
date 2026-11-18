package detection

import (
	"xe-antishell/internal/capability"
	"xe-antishell/internal/model"
)

const (
	baseRuleVersion                      = "0.1.0"
	ruleWebDescendantRootShell           = "web-descendant-root-shell"
	ruleWebDescendantShell               = "web-descendant-shell"
	ruleWebDescendantDownloadTool        = "web-descendant-download-tool"
	ruleWebDescendantReconTool           = "web-descendant-recon-tool"
	ruleWebDescendantConnectionTool      = "web-descendant-connection-tool"
	ruleWebDescendantInlineInterpreter   = "web-descendant-inline-interpreter"
	ruleWebDescendantTemporaryExecutable = "web-descendant-temporary-executable"
	ruleWebDescendantTemporaryScript     = "web-descendant-temporary-script"
	rulePrivilegeRootExecution           = "privilege-root-execution"
	rulePrivilegeRootRestored            = "privilege-root-restored"
	rulePrivilegeHostRootGain            = "privilege-host-root-gain"
	rulePrivilegeRootIdentityChange      = "privilege-root-identity-change"
	rulePrivilegeCapabilityGain          = "privilege-capability-gain"
	rulePrivilegeCapabilityActivated     = "privilege-capability-activated"
)

var builtinRules = [...]struct{ id, profile, title, description string }{
	{ruleWebDescendantRootShell, "base", "웹 서비스에서 관리자 권한 셸 실행",
		"서비스가 운영체제 명령을 실행했습니다. 정상 배포 작업인지 확인하세요."},
	{ruleWebDescendantShell, "base", "웹 서비스에서 셸 실행",
		"서비스가 운영체제 명령을 실행했습니다. 정상 배포 작업인지 확인하세요."},
	{ruleWebDescendantDownloadTool, "extended", "웹 서비스에서 다운로드 도구 실행",
		"다운로드 기능이 있는 도구가 실행됐습니다. 실제 다운로드 여부와 정상 운영 작업인지는 추가 확인이 필요합니다."},
	{ruleWebDescendantReconTool, "extended", "웹 서비스에서 정보 확인 도구 실행",
		"시스템·계정·네트워크 정보 확인용 도구가 실행됐습니다. 정상 운영 작업인지 확인하세요."},
	{ruleWebDescendantConnectionTool, "extended", "웹 서비스에서 연결 도구 실행",
		"연결 기능이 있는 도구가 실행됐습니다. 실제 연결 여부와 실행 목적은 추가 확인이 필요합니다."},
	{ruleWebDescendantInlineInterpreter, "extended", "웹 서비스에서 직접 코드 실행 요청",
		"직접 코드 실행 옵션을 지정한 인터프리터가 실행됐습니다. 코드 내용과 실행 성공 여부는 이 기록으로 확인할 수 없습니다."},
	{ruleWebDescendantTemporaryExecutable, "extended", "웹 서비스에서 임시 경로의 실행 파일 실행",
		"임시 또는 메모리 파일 경로의 프로그램이 실행됐습니다. 파일의 출처와 정상 운영 작업인지는 추가 확인이 필요합니다."},
	{ruleWebDescendantTemporaryScript, "extended", "웹 서비스에서 임시 경로의 스크립트 실행 요청",
		"인터프리터에 임시·메모리·파일 디스크립터 경로의 스크립트가 지정됐습니다. 파일 내용과 실행 성공 여부는 이 기록으로 확인할 수 없습니다."},
	{ruleServiceProtectedFileWrite, "file", "서비스 보호 경로에 파일 쓰기",
		"호스트에 지정한 보호 경로에 서비스가 실제 바이트를 썼습니다. 쓰기 예외는 제외합니다."},
	{ruleServiceUnexpectedTCPDestination, "network", "서비스 허용 범위 밖의 TCP 연결 시작",
		"호스트에 지정한 주소·포트 범위 밖으로 서비스가 TCP 연결을 시작했습니다. 연결 결과와 전송 내용은 추가 확인이 필요합니다."},
	{rulePrivilegeRootExecution, "privilege", "전역 root 실행 관측",
		"EUID 0 실행과 주변 문맥을 관측했습니다. 승인된 작업인지 확인하세요."},
	{rulePrivilegeRootRestored, "privilege", "기존 root 자격으로 실행 권한 복귀",
		"같은 user namespace에서 UID 또는 saved UID 0을 가진 작업이 EUID 0으로 복귀했습니다. 인증·인가가 확인됐다는 뜻은 아닙니다."},
	{rulePrivilegeHostRootGain, "privilege", "초기 user namespace의 root 권한 변경",
		"같은 초기 user namespace에서 EUID 비0→0 적용을 관측했습니다. 승인된 권한 상승인지 확인하세요. 컨테이너 탈출을 확정하지 않습니다."},
	{rulePrivilegeRootIdentityChange, "privilege", "root 실행 신원 변경 관측",
		"EUID 비0→0 적용을 관측했습니다. namespace가 다르거나 확인되지 않을 수 있으므로 호스트 권한 탈취로 단정하지 않습니다."},
	{rulePrivilegeCapabilityGain, "privilege", "프로세스 Capability 권한집합 증가",
		"보유 권한집합이 늘어난 것을 관측했습니다. user namespace와 승인된 작업 범위를 확인하세요."},
	{rulePrivilegeCapabilityActivated, "privilege", "기존 Capability의 실행 권한 활성화",
		"이미 permitted에 있던 권한이 effective로 활성화됐습니다. 새 permitted 권한 획득과 구분해 확인하세요."},
}

// RuleDefinitions returns owned metadata for every built-in finding ID. Stored
// findings retain their original version regardless of the current profile.
func RuleDefinitions() []model.RuleStatus {
	rules := make([]model.RuleStatus, 0, len(builtinRules))
	for _, def := range builtinRules {
		rule := model.RuleStatus{
			ID: def.id, Title: def.title, Description: def.description, Profile: def.profile,
			Version: extendedRuleVersion, Response: "detection_only",
			EventTypes: []string{"process.exec"}, RequiredFields: []string{"process.exe", "process.origin_service | ancestors[].exe | ancestors[].origin_service"},
			Sensors: []model.RuleSensor{{Name: capability.ProcessExecCapability}},
		}
		switch def.profile {
		case "base":
			rule.Version, rule.Response = baseRuleVersion, "observe"
			if def.id == ruleWebDescendantRootShell {
				rule.RequiredFields = append(rule.RequiredFields, "process.euid")
			}
		case "file", "network":
			rule.Version = operationRuleVersion
			rule.RequiredFields = append([]string(nil), operationIdentityFields[:]...)
			if def.profile == "file" {
				rule.EventTypes = []string{"file.write"}
				rule.Sensors = []model.RuleSensor{{Name: capability.FileCapability, RequiredCollector: "tetragon-json"}}
				rule.RequiredFields = append(rule.RequiredFields, "file.policy_name", "file.function", "file.operation", "file.path", "file.outcome", "file.return_value")
			} else {
				rule.EventTypes = []string{"network.connect"}
				rule.Sensors = []model.RuleSensor{{Name: capability.NetworkCapability, RequiredCollector: "tetragon-json"}}
				rule.RequiredFields = append(rule.RequiredFields, "network.policy_name", "network.function", "network.operation", "network.family", "network.protocol", "network.destination_address", "network.destination_port", "network.outcome", "network.return_value")
			}
		case "privilege":
			rule.Version = privilegeRuleVersion
			if def.id == rulePrivilegeRootExecution {
				rule.RequiredFields = []string{"process.exe", "process.euid"}
			} else {
				rule.EventTypes = []string{"process.credential_change"}
				rule.Sensors = []model.RuleSensor{{Name: capability.CredentialCapability, RequiredCollector: "tetragon-json"}}
				// An applied outcome requires complete snapshots from the fixed hook.
				rule.RequiredFields = []string{
					"boot_id", "process.pid", "process.exec_id", "process.start_time", "event_time",
					"credential.policy_name", "credential.evidence", "credential.function",
					"credential.tgid", "credential.tid", "credential.task_start_time_ns",
					"credential.before", "credential.after", "credential.outcome", "credential.return_value",
				}
				switch def.id {
				case rulePrivilegeHostRootGain:
					rule.RequiredFields = append(rule.RequiredFields, "credential.before.uid", "credential.before.suid", "credential.before.user_namespace", "credential.after.user_namespace")
				case rulePrivilegeRootRestored:
					rule.RequiredFields = append(rule.RequiredFields, "credential.before.uid | credential.before.suid", "credential.before.user_namespace", "credential.after.user_namespace")
				case rulePrivilegeCapabilityGain, rulePrivilegeCapabilityActivated:
					rule.RequiredFields = append(rule.RequiredFields, "credential.before.capabilities", "credential.after.capabilities")
				}
			}
		}
		switch def.id {
		case ruleWebDescendantInlineInterpreter:
			rule.EventTypes = append(rule.EventTypes, "process.exec_observation")
			rule.Sensors = []model.RuleSensor{{Name: capability.InterpreterCapability}}
			rule.RequiredFields = append(rule.RequiredFields, "execution.runtime", "execution.mode", "execution.evidence", "execution.option")
		case ruleWebDescendantTemporaryScript:
			rule.Sensors = []model.RuleSensor{{Name: capability.InterpreterCapability, RequiredCollector: "audit-dispatcher"}}
			rule.RequiredFields = append(rule.RequiredFields, "execution.runtime", "execution.mode", "execution.evidence", "execution.script_location")
		}
		rules = append(rules, rule)
	}
	return rules
}

// Rules applies the same immutable options used by Evaluate.
func (e *Engine) Rules(enabled bool) []model.RuleStatus {
	rules := RuleDefinitions()
	webOrigins := len(e.webServices) > 0 || len(e.webExecutables) > 0
	var fileScope, networkScope bool
	for _, scope := range e.serviceObservations {
		fileScope = fileScope || len(scope.ProtectedDirs) > 0
		networkScope = networkScope || len(scope.AllowedTCPDestinations) > 0
	}
	for i := range rules {
		r := &rules[i]
		if r.Profile == "base" && e.extendedProcessRules {
			r.Version, r.Response = extendedRuleVersion, "detection_only"
		}
		switch {
		case !enabled:
			r.Reason = "정책에서 전체 탐지가 꺼져 있습니다."
		case r.Profile == "file" && !fileScope:
			r.Reason = "현재 웹 서비스와 일치하는 호스트 보호 경로 설정이 없습니다."
		case r.Profile == "network" && !networkScope:
			r.Reason = "현재 웹 서비스와 일치하는 호스트 TCP 허용 목록이 없습니다."
		case r.Profile == "privilege" && !e.privilegeRules:
			r.Reason = "권한 탐지 프로필이 꺼져 있습니다."
		case r.Profile == "extended" && !e.extendedProcessRules:
			r.Reason = "확장 프로세스 프로필이 꺼져 있습니다."
		case r.Profile != "privilege" && !webOrigins:
			r.Reason = "정책에 웹 출처가 없습니다."
		case r.Profile == "base" && len(e.shells) == 0:
			r.Reason = "정책에 탐지할 셸이 없습니다."
		case r.Profile == "base" && e.allShellPairsAllowed():
			r.Reason = "모든 웹 출처와 셸 조합이 정책 예외에 포함됩니다."
		default:
			r.Enabled = true
			if r.ID == rulePrivilegeRootExecution && e.rootExecAlerts != "all" {
				r.Reason = "의심 문맥 점수가 기준에 도달한 root 실행만 경보를 만듭니다."
			}
		}
	}
	return rules
}

func (e *Engine) allShellPairsAllowed() bool {
	if len(e.allowedPairs) == 0 {
		return false
	}
	for _, origins := range []map[string]struct{}{e.webExecutables, e.webServices} {
		for origin := range origins {
			for shell := range e.shells {
				if _, ok := e.allowedPairs[origin+":"+shell]; !ok {
					return false
				}
			}
		}
	}
	return true
}
