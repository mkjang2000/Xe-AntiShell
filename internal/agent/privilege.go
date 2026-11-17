package agent

import (
	"context"
	"time"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/model"
	"xe-antishell/internal/privileges"
)

const privilegeEngineCapability = "detection.privilege_rules"

func (s *Service) privilegeEnabled() bool {
	state := s.detectionState.Load()
	return state != nil && state.enabled && state.engine.PrivilegeEnabled()
}

func (s *Service) privilegeLoop(ctx context.Context) {
	defer s.producerWG.Done()
	if s.privilegeController == nil || !managedWait(ctx, 8*time.Second) {
		return
	}
	for {
		enabled := s.privilegeEnabled() && s.currentCollectorName() == "tetragon-json"
		s.privilegeController.Reconcile(ctx, enabled)
		if !managedWait(ctx, 15*time.Second) {
			return
		}
	}
}

// Static support authorizes a new policy; only live paired receipts establish
// active credential monitoring. The first cannot depend on the second.
func (s *Service) applyPrivilegeCapabilities(status *model.AgentStatus, report *model.CapabilityReport, evidence sourceRuntimeEvidence) {
	engine := model.Capability{Name: privilegeEngineCapability, Provider: "local-detector", Implementation: "implemented", State: model.CapabilityLimited, RuntimeState: "inactive", Reason: "전역 root 실행·권한 변경 탐지 엔진", RuntimeReason: "호환되는 Tetragon 수집기와 설치된 정책 컨트롤러가 필요합니다.", Details: map[string]string{"contract": "1", "response": "detection_only"}}
	supported := s.privilegeController != nil && s.privilegeController.Snapshot().Supported && status.Collector == "tetragon-json" && privilegeArgumentsUsable(s.config.Collector.Tetragon.Args)
	if !privilegeArgumentsUsable(s.config.Collector.Tetragon.Args) {
		engine.State = model.CapabilityUnsupported
		engine.RuntimeReason = "수집 인자가 전역 실행·권한 변경 근거를 누락할 수 있어 이 프로필을 지원하지 않습니다."
	}
	if supported {
		engine.State = model.CapabilitySupported
		engine.RuntimeState = "available"
		engine.RuntimeReason = "중앙 정책으로 활성화할 수 있습니다. 실제 권한 변경 수신 여부는 별도로 확인합니다."
		if s.privilegeEnabled() {
			engine.RuntimeState = "active"
			engine.RuntimeReason = "권한 탐지 프로필이 활성화됐습니다. 새 규칙은 탐지 전용입니다."
		}
	}
	report.Capabilities[privilegeEngineCapability] = engine
	value, ok := report.Capabilities[capability.CredentialCapability]
	if !ok {
		value = model.Capability{Name: capability.CredentialCapability, State: model.CapabilityLimited, Provider: "tetragon", Implementation: "implemented"}
	}
	value.Implementation = "implemented"
	if !s.privilegeEnabled() {
		value.RuntimeState = "inactive"
		value.RuntimeReason = "권한 변경 관측이 정책에서 꺼져 있습니다."
		value.VerifiedAt = nil
	} else if !supported {
		value.RuntimeState = "inactive"
		value.RuntimeReason = "이 설치에서는 고정 권한 변경 정책을 제어할 수 없습니다."
		value.VerifiedAt = nil
	} else {
		control := s.privilegeController.Snapshot()
		if value.Details == nil {
			value.Details = map[string]string{}
		}
		value.Details["controller_error"] = control.Error
		value.Details["policy_loaded"] = "false"
		if control.Loaded {
			value.Details["policy_loaded"] = "true"
		}
		if control.Error != "" {
			value.RuntimeState = "error"
			value.RuntimeReason = "고정 권한 변경 정책 적용 상태를 확인하세요: " + control.Error
			value.VerifiedAt = nil
			if status.Health != model.HealthError {
				status.Health = model.HealthDegraded
			}
			if status.LastError != "" {
				status.LastError += "; "
			}
			status.LastError += "credential policy: " + control.Error
		} else if !control.Loaded || evidence.CredentialAt.IsZero() || evidence.CredentialAt.Before(control.GenerationAt) {
			if value.RuntimeState != "error" {
				value.RuntimeState = "unverified"
				value.RuntimeReason = "정책 적용 후 동일 훅의 변경 전·후와 반환값을 담은 실제 이벤트를 기다립니다."
				value.VerifiedAt = nil
			}
		}
	}
	report.Capabilities[capability.CredentialCapability] = value
}

// Credential observations bypass web-only retention, but never enable actions.
// A collector argument that filters out kernel events cannot be repaired here.
func privilegeArgumentsUsable(args []string) bool {
	return privileges.EventArgumentsUsable(args)
}
