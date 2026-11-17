package agent

import (
	"errors"
	"strings"

	"xe-antishell/internal/model"
)

// Operation errors overlay collector state, so evidence recovery cannot revive
// a stopped collector or clear an unrelated bootstrap/maintenance failure.
func (s *Service) setOperationError(operation string, err error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if s.operationErrors == nil {
		s.operationErrors = make(map[string]string)
	}
	s.operationErrors[operation] = err.Error()
}

func (s *Service) clearOperationError(operation string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	delete(s.operationErrors, operation)
}

// Caller holds statusMu. No sensitive payload is added to diagnostics here.
func (s *Service) operationStatus(status model.AgentStatus) model.AgentStatus {
	parts := []string{}
	if status.LastError != "" {
		parts = append(parts, status.LastError)
	}
	for _, operation := range []string{"event_store", "response", "retention"} {
		message := s.operationErrors[operation]
		if message == "" {
			continue
		}
		parts = append(parts, message)
		if operation == "retention" {
			if status.Mode == model.AgentModeActive {
				status.Mode = model.AgentModeDegraded
			}
			if status.Health != model.HealthError {
				status.Health = model.HealthDegraded
			}
		} else {
			status.Mode, status.Health = model.AgentModeError, model.HealthError
		}
	}
	status.LastError = strings.Join(parts, "; ")
	return status
}

func (s *Service) recordOperationalError(err error) {
	if err == nil {
		err = errors.New("retention failed")
	}
	s.setOperationError("retention", err)
}
