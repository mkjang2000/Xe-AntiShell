package agent

import (
	"context"
	"path/filepath"
	"strings"

	"xe-antishell/internal/detection"
	"xe-antishell/internal/model"
)

// Tetragon delivers source exec identities for parents that may predate the
// subscriber. Seed that context without inventing additional execution events.
func (s *Service) observeTetragonAncestors(ctx context.Context, event *model.Event) {
	for index := len(event.Ancestors) - 1; index >= 0; index-- {
		process := event.Ancestors[index]
		if process.Key == "" || process.PID < 1 {
			continue
		}
		if known, ok := s.lineage.Get(process.Key); ok {
			event.Ancestors[index] = known
			continue
		}
		current, hasCurrent := s.lineage.CurrentByPID(process.PID)
		conflictingIdentity := hasCurrent && current.ExecID != "" && current.ExecID != process.ExecID
		if hasCurrent && current.Exe == process.Exe && !conflictingIdentity &&
			!current.StartTime.After(process.StartTime) {
			// Bootstrap keys use procfs start time; retain their service origin
			// only if there is no conflicting source exec identity.
			process.OriginService = current.OriginService
		}
		if process.OriginService == "" && !conflictingIdentity {
			process.OriginService, _ = s.processSource.OriginService(ctx, process.PID)
		}
		event.Ancestors[index] = s.lineage.ObserveContext(process)
	}
}

func (s *Service) retainTetragonEvent(event model.Event) bool {
	return s.retainTetragonEventWithDetector(event, s.detectionState.Load().engine)
}

func (s *Service) retainTetragonEventWithDetector(event model.Event, detector *detection.Engine) bool {
	if detector.IsPrivilegeCandidate(event) {
		return true
	}
	if event.Type == "process.credential_change" {
		return false
	}
	if isOperationEvent(event.Type) {
		_, matched := detector.MatchWebOrigin(event, s.lineage)
		return matched
	}
	policy := s.config.Collector.Tetragon
	if len(policy.IncludeExecutables) != 0 {
		name := strings.ToLower(filepath.Base(event.Process.Exe))
		included := false
		for _, allowed := range policy.IncludeExecutables {
			if strings.EqualFold(name, allowed) {
				included = true
				break
			}
		}
		if !included {
			return false
		}
	}
	if policy.OnlyDetectionOrigins {
		_, matched := detector.MatchWebOrigin(event, s.lineage)
		return matched
	}
	return true
}
