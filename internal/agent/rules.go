package agent

import (
	"context"
	"errors"
	"time"

	"xe-antishell/internal/model"
)

func (s *Service) Rules(ctx context.Context) (model.RuleCatalog, error) {
	if err := ctx.Err(); err != nil {
		return model.RuleCatalog{}, err
	}
	state := s.detectionState.Load()
	if state == nil || state.engine == nil {
		return model.RuleCatalog{}, errors.New("detector policy unavailable")
	}
	status, report := s.runtimeSnapshotFor(state)
	catalog := model.RuleCatalog{PolicySource: "local", ServiceObservationSource: state.serviceObservationSource(), Collector: status.Collector, Rules: state.engine.Rules(state.enabled)}
	mode := "observe"
	if policy := state.policy; policy != nil {
		catalog.PolicySource, catalog.PolicyRevision = "managed", policy.Revision
		if time.Now().Before(policy.ExpiresAt) {
			switch policy.Response.Mode {
			case "would_block":
				mode = "would_block"
			case "enforce":
				if s.config.Response.AllowTerminate && catalog.Collector == "tetragon-json" {
					mode = "enforce"
				}
			}
		}
	}
	for i := range catalog.Rules {
		rule := &catalog.Rules[i]
		if rule.Enabled && rule.Response != "detection_only" {
			rule.Response = mode
		}
		for j := range rule.Sensors {
			sensor := &rule.Sensors[j]
			cap := report.Capabilities[sensor.Name]
			switch {
			case sensor.RequiredCollector != "" && sensor.RequiredCollector != catalog.Collector:
				sensor.State = "inactive"
				if rule.Enabled {
					rule.Reason = "이 규칙의 실시간 근거는 " + sensor.RequiredCollector + " 수집기가 필요합니다."
				}
			case sourceForCollector(catalog.Collector) == "":
				sensor.State = "inactive"
			case cap.RuntimeState == "active" && cap.Implementation == "implemented" && cap.VerifiedAt != nil && !cap.VerifiedAt.IsZero():
				sensor.State, sensor.VerifiedAt = "active", cap.VerifiedAt
			case cap.RuntimeState == "inactive" || cap.RuntimeState == "error" || cap.RuntimeState == "available":
				sensor.State = cap.RuntimeState
			default:
				sensor.State = "unverified"
			}
		}
	}
	return catalog, nil
}
