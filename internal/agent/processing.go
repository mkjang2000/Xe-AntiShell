package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

// generation is local queue metadata. Source and persisted event identities
// must stay stable across subscriptions.
type queuedEvent struct {
	model.Event
	generation  uint64
	submittedAt time.Time
	detection   *detectionState
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
	state := item.detection
	if state == nil {
		state = s.detectionState.Load()
	}
	if err := s.processCapturedObservation(context.Background(), &item.Event, item.generation, item.submittedAt, time.Now(), state); err != nil {
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

func (s *Service) processObservation(ctx context.Context, event *model.Event, generation uint64, submittedAt, evaluationTime time.Time) error {
	return s.processCapturedObservation(ctx, event, generation, submittedAt, evaluationTime, s.detectionState.Load())
}

func (s *Service) processCapturedObservation(ctx context.Context, event *model.Event, generation uint64, submittedAt, evaluationTime time.Time, detection *detectionState) error {
	if err := s.normalizeEvent(event); err != nil {
		s.parseErrs.Add(1)
		s.updateCounters()
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	s.recordRuntimeEvent(*event, generation)
	if event.Source == "tetragon" && !isOperationEvent(event.Type) {
		s.observeTetragonAncestors(ctx, event)
	}

	var app *applicationDetector
	switch event.Type {
	case "process.exec":
		if event.Process.PID > 0 && event.Process.OriginService == "" {
			current, known := s.lineage.CurrentByPID(event.Process.PID)
			if !known || !current.StartTime.After(event.Process.StartTime) {
				event.Process.OriginService, _ = s.processSource.OriginService(ctx, event.Process.PID)
			}
		}
		app = s.applicationForEvent(ctx, *event, detection)
		if app == nil && event.Source == "audit" && s.config.Collector.Audit.OnlyDetectionOrigins && !detection.engine.IsPrivilegeCandidate(*event) {
			if _, matched := detection.engine.MatchWebOrigin(*event, s.lineage); !matched {
				return nil
			}
		}
		directService := event.Process.OriginService
		s.lineage.Observe(event)
		if directService == "" && event.Process.OriginService != "" {
			event.MissingFields = appendUnique(event.MissingFields, model.DirectServiceEvidence)
		}
		s.recordRuntimeEvent(*event, generation)
	case "process.credential_change", "process.exec_observation", "file.write", "network.connect":
		if err := s.observeOperationContext(ctx, event); err != nil {
			return &eventProcessingError{operation: "event_store", cause: err}
		}
		app = s.applicationForEvent(ctx, *event, detection)
	case "process.exit":
		if process, ok := s.lineage.ExitObserved(event.Process.Key, event.Process.PID, event.EventTime, event.IngestTime); ok {
			event.Process = process
		}
	}
	if event.Source == "tetragon" && !s.retainTetragonEventWithDetector(*event, detection.engine, app != nil) {
		return nil
	}

	findings := s.evaluateObservation(*event, detection, app, evaluationTime)
	// Evidence, derived findings, and managed delivery are one durable unit.
	inserted, err := s.store.PersistObservationWithHistory(ctx, *event, findings, s.observationHistoryMinutes() > 0)
	if err != nil {
		return &eventProcessingError{operation: "event_store", cause: err}
	}
	if inserted && !submittedAt.IsZero() {
		latency := uint64(time.Since(submittedAt))
		observeMax(&s.capacity.maxLatency, latency)
		s.capacity.lastLatency.Store(latency)
	}
	s.markEventProcessed(event.IngestTime, generation, inserted)
	// A retry can finish a previously approved pending response, but a changed
	// policy or an expired exception must never create a new response to old input.
	if !inserted {
		for i := range findings {
			if findings[i].ResponseDecision != "terminate_pending" {
				continue
			}
			saved, err := s.store.GetFinding(ctx, findings[i].ID)
			if errors.Is(err, storage.ErrNotFound) || err == nil && !sameFindingPolicy(saved, findings[i]) {
				findings[i].ResponseDecision = "observe"
				continue
			}
			if err != nil {
				return &eventProcessingError{operation: "response", cause: err}
			}
			findings[i] = saved
		}
	}
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

func sameFindingPolicy(a, b model.Finding) bool {
	return a.PolicyRevision == b.PolicyRevision && a.ApplicationService == b.ApplicationService &&
		a.ApplicationPolicyID == b.ApplicationPolicyID && a.ApplicationPolicyVersion == b.ApplicationPolicyVersion
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
