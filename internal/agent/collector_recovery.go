package agent

import (
	"context"
	"errors"
	"strconv"
	"time"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/collector"
	"xe-antishell/internal/model"
)

const maxCollectorRetryDelay = 30 * time.Second

// Protected by statusMu. The generation advances as soon as a stream ends,
// before another subscription can start or an old queued event can claim recovery.
type collectorRecovery struct {
	generation     uint64
	attempts       uint64
	disconnectedAt time.Time
	recoveredAt    time.Time
}

func (s *Service) runCollector(ctx context.Context, source collector.Collector) {
	defer s.producerWG.Done()
	s.markCollectorRunning(source.Name())
	if source.Name() == "tetragon-json" {
		s.runTetragon(ctx, source, managedWait)
		return
	}
	err := source.Run(ctx, s)
	if ctx.Err() == nil {
		health, cause := streamEnd(err)
		s.setRuntimeState(model.AgentModeDegraded, health, source.Name(), cause)
	}
}

func (s *Service) runTetragon(ctx context.Context, source collector.Collector, wait func(context.Context, time.Duration) bool) {
	delay := time.Second
	for ctx.Err() == nil {
		s.statusMu.Lock()
		generation := s.recovery.generation
		if generation != 0 {
			s.recovery.attempts++
		}
		s.statusMu.Unlock()

		err := source.Run(ctx, collector.SinkFunc(func(ctx context.Context, event model.Event) error {
			return s.submit(ctx, event, generation)
		}))
		if ctx.Err() != nil {
			return
		}
		if s.recordCollectorDisconnect(err) {
			delay = time.Second
		}
		if !wait(ctx, delay) {
			return
		}
		delay = min(delay*2, maxCollectorRetryDelay)
	}
}

func streamEnd(err error) (model.Health, error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return model.HealthDegraded, errors.New("collector stream ended")
	}
	return model.HealthError, err
}

// Returns true on the first disconnect of a new gap. Failed retries preserve
// its start and continue backing off until a new subscription commits a new event.
func (s *Service) recordCollectorDisconnect(err error) bool {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	r := &s.recovery
	newGap := r.disconnectedAt.IsZero() || !r.recoveredAt.IsZero()
	if newGap {
		r.disconnectedAt = time.Now().UTC()
		r.recoveredAt = time.Time{}
	}
	r.generation++
	delete(s.runtimeEvidence, "tetragon")
	health, cause := streamEnd(err)
	s.status.Mode, s.status.Health = model.AgentModeDegraded, health
	s.status.LastError = cause.Error()
	return newGap
}

func (r collectorRecovery) addDetails(report *model.CapabilityReport) {
	if r.disconnectedAt.IsZero() {
		return
	}
	value := report.Capabilities[capability.TetragonCapability]
	if value.Details == nil {
		value.Details = make(map[string]string)
	}
	value.Details["last_disconnect_at"] = r.disconnectedAt.Format(time.RFC3339Nano)
	value.Details["reconnect_attempts"] = strconv.FormatUint(r.attempts, 10)
	if !r.recoveredAt.IsZero() {
		value.Details["last_recovered_at"] = r.recoveredAt.Format(time.RFC3339Nano)
	}
	report.Capabilities[capability.TetragonCapability] = value
}
