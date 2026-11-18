package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"xe-antishell/internal/model"
)

// generation is local queue metadata. Source and persisted event identities
// must stay stable across subscriptions.
type queuedEvent struct {
	model.Event
	generation  uint64
	submittedAt time.Time
}

type eventProcessingError struct {
	operation string
	cause     error
}

func (e *eventProcessingError) Error() string { return e.cause.Error() }
func (e *eventProcessingError) Unwrap() error { return e.cause }

func (s *Service) processLoop() {
	defer s.processorWG.Done()
	for {
		select {
		case event := <-s.eventQueue:
			s.processQueuedEvent(event)
		case <-s.processorStop:
			for {
				select {
				case event := <-s.eventQueue:
					s.processQueuedEvent(event)
				default:
					return
				}
			}
		}
	}
}

func (s *Service) processQueuedEvent(item queuedEvent) {
	if item.generation > s.processedGeneration {
		// Exec/exit may have been missed during the gap. Keep history by exact
		// execution identity, but rebuild PID-only attribution from new input.
		s.lineage.ForgetCurrentPIDs()
		s.processedGeneration = item.generation
	}
	if err := s.processObservation(context.Background(), &item.Event, item.generation, item.submittedAt); err != nil {
		s.recordProcessingFailure(err)
	}
}

// A failed post-commit response is not a lost observation.
func (s *Service) recordProcessingFailure(err error) {
	if errors.Is(err, ErrInvalidEvent) {
		s.drop(dropInvalid, 1)
		s.updateCounters()
		return
	}
	var operation *eventProcessingError
	if errors.As(err, &operation) && operation.operation == "response" {
		s.setOperationError("response", err)
	} else {
		s.drop(dropStorage, 1)
		s.setOperationError("event_store", err)
	}
	s.updateCounters()
}

func (s *Service) processObservation(ctx context.Context, event *model.Event, generation uint64, submittedAt time.Time) error {
	detection := s.detectionState.Load()
	if err := s.normalizeEvent(event); err != nil {
		s.parseErrs.Add(1)
		s.updateCounters()
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	s.recordRuntimeEvent(*event, generation)
	if event.Source == "tetragon" && !isOperationEvent(event.Type) {
		s.observeTetragonAncestors(ctx, event)
	}

	switch event.Type {
	case "process.exec":
		if event.Process.PID > 0 && event.Process.OriginService == "" {
			if origin, err := s.processSource.OriginService(ctx, event.Process.PID); err == nil {
				event.Process.OriginService = origin
			}
		}
		if event.Source == "audit" && s.config.Collector.Audit.OnlyDetectionOrigins && !detection.engine.IsPrivilegeCandidate(*event) {
			if _, matched := detection.engine.MatchWebOrigin(*event, s.lineage); !matched {
				return nil
			}
		}
		s.lineage.Observe(event)
		s.recordRuntimeEvent(*event, generation)
	case "process.credential_change", "process.exec_observation", "file.write", "network.connect":
		if err := s.observeOperationContext(ctx, event); err != nil {
			return &eventProcessingError{operation: "event_store", cause: err}
		}
	case "process.exit":
		if process, ok := s.lineage.ExitObserved(event.Process.Key, event.Process.PID, event.EventTime, event.IngestTime); ok {
			event.Process = process
		}
	}
	if event.Source == "tetragon" && !s.retainTetragonEventWithDetector(*event, detection.engine) {
		return nil
	}

	var findings []model.Finding
	if detection.enabled {
		findings = detection.engine.Evaluate(*event, s.lineage)
		s.applyResponseDecisions(findings, detection.policy)
		for index := range findings {
			if findings[index].DetectionOnly {
				continue
			}
			if previous, err := s.store.GetFinding(ctx, findings[index].ID); err == nil && (previous.ResponseDecision == "sigterm_sent" || previous.ResponseDecision == "refused" || previous.ResponseDecision == "not_repeated") {
				findings[index] = previous
			}
		}
	}
	// Evidence, derived findings, and managed delivery are one durable unit.
	inserted, err := s.store.PersistObservationWithHistory(ctx, *event, findings, s.config.Limits.ObservationHistoryMinutes > 0)
	if err != nil {
		return &eventProcessingError{operation: "event_store", cause: err}
	}
	if inserted && !submittedAt.IsZero() {
		latency := uint64(time.Since(submittedAt))
		observeMax(&s.capacity.maxLatency, latency)
		s.capacity.lastLatency.Store(latency)
	}
	s.markEventProcessed(event.IngestTime, generation, inserted)
	responseAttempted := false
	for _, finding := range findings {
		responseAttempted = responseAttempted || (!finding.DetectionOnly && finding.ResponseDecision == "terminate_pending")
	}
	if err := s.executeResponses(ctx, *event, findings, detection.policy); err != nil {
		return &eventProcessingError{operation: "response", cause: err}
	}
	if responseAttempted {
		s.clearOperationError("response")
	}
	return nil
}

func (s *Service) markEventProcessed(at time.Time, generation uint64, inserted bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.LastEventAt = &at
	delete(s.operationErrors, "event_store")
	if inserted && generation != 0 && generation == s.recovery.generation && s.recovery.recoveredAt.IsZero() {
		s.recovery.recoveredAt = time.Now().UTC()
		s.status.Mode = model.AgentModeActive
		s.status.LastError = ""
		if s.bootstrapErr != nil {
			s.status.Health = model.HealthDegraded
			s.status.LastError = s.bootstrapErr.Error()
		}
	}
	if s.status.Mode == model.AgentModeActive && s.bootstrapErr == nil && s.status.LastError == "" {
		s.status.Health = model.HealthHealthy
	} else if s.status.Mode == model.AgentModeDegraded && s.status.Health != model.HealthError {
		s.status.Health = model.HealthDegraded
	}
	s.status.Dropped = s.dropped.Load()
	s.status.ParseErrors = s.parseErrs.Load()
}
