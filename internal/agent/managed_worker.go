package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/hostmetrics"
	"xe-antishell/internal/storage"
)

const (
	managedDeliveryIdle        = time.Second
	managedDeliveryMaxBackoff  = time.Minute
	managedDeliveryBurstBatch  = 8
	managedDeliveryBurstBudget = 250 * time.Millisecond
	managedDeliveryYield       = 50 * time.Millisecond
)

func (s *Service) startManagedWorkers(ctx context.Context) {
	if _, state, err := s.managedConnection(ctx); err == nil {
		if signed, err := s.store.Policy(ctx); err == nil {
			if err := s.applyManagedPolicy(ctx, signed, state, time.Now().UTC(), true); err != nil {
				s.managedPolicyError(err)
			}
		} else if !errors.Is(err, storage.ErrNotFound) {
			s.managedError("policy", "read approved policy failed")
		}
	} else if !errors.Is(err, storage.ErrNotFound) {
		s.managedError("identity", "stored central identity is invalid")
	}
	if enrolled, err := s.store.ManagedState(ctx); err == nil {
		s.agentConfigurationRestoreFailed.Store(s.restoreAgentConfiguration(ctx, enrolled) != nil)
	} else if !errors.Is(err, storage.ErrNotFound) {
		s.agentConfigurationRestoreFailed.Store(true)
	}
	// Keep durable policy restoration above synchronous. Spread optional work
	// across startup; collector acceptance and the local API remain immediate.
	for _, worker := range []struct {
		delay time.Duration
		run   func(context.Context)
	}{
		{time.Second, s.managedDeliveryLoop},
		{3 * time.Second, s.managedHeartbeatLoop},
		{5 * time.Second, s.managedPolicyLoop},
		{7 * time.Second, s.managedUpdateLoop},
		{11 * time.Second, s.managedFileIntegrityLoop},
		{13 * time.Second, s.pollAgentConfiguration},
		{17 * time.Second, s.managedRemoteRemovalLoop},
		{4 * time.Second, s.managedResourceSamplerLoop},
	} {
		s.producerWG.Add(1)
		go func(delay time.Duration, run func(context.Context)) {
			defer s.producerWG.Done()
			if managedWait(ctx, delay) {
				run(ctx)
			}
		}(worker.delay, worker.run)
	}
}

func managedWait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Service) managedDeliveryLoop(ctx context.Context) {
	runManagedDelivery(ctx, func(ctx context.Context) (bool, error) {
		s.managedRuntime.senderMu.Lock()
		defer s.managedRuntime.senderMu.Unlock()
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return s.deliverManagedBatch(ctx)
	}, managedWait, time.Now)
}

// Drain acknowledged backlog without imposing the idle poll interval on every
// batch. Both batch/time limits plus a cancellable yield bound continuous load;
// one slow request still respects the client's existing request deadline.
func runManagedDelivery(ctx context.Context, deliver func(context.Context) (bool, error), wait func(context.Context, time.Duration) bool, now func() time.Time) {
	backoff := managedDeliveryIdle
	for ctx.Err() == nil {
		started := now()
		delay := managedDeliveryYield
		for batch := 0; batch < managedDeliveryBurstBatch; batch++ {
			if ctx.Err() != nil {
				return
			}
			empty, err := deliver(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				backoff *= 2
				if backoff > managedDeliveryMaxBackoff {
					backoff = managedDeliveryMaxBackoff
				}
				delay = backoff
				break
			}
			backoff = managedDeliveryIdle
			if empty || err != nil {
				delay = managedDeliveryIdle
				break
			}
			if now().Sub(started) >= managedDeliveryBurstBudget {
				break
			}
		}
		if !wait(ctx, delay) {
			return
		}
	}
}

func (s *Service) managedHeartbeatLoop(ctx context.Context) {
	for {
		monitoring := s.currentMonitoring()
		settings := s.approvedAgentConfiguration()
		interval := time.Second * time.Duration(s.heartbeatInterval(monitoring, settings))
		client, state, err := s.managedConnection(ctx)
		if err == nil {
			status, _ := s.Status(ctx)
			s.managedRuntime.mu.RLock()
			policy := s.managedRuntime.status.Policy
			s.managedRuntime.mu.RUnlock()
			var resources json.RawMessage
			if monitoring.Enabled {
				if samplingManaged(settings) {
					if sample := s.managedResourceCache.Load(); sample != nil {
						resources = sample.data
					}
				} else {
					resources = s.managedResources(ctx)
				}
			}
			heartbeat := managed.Heartbeat{AgentID: state.AgentID, EnrollmentID: state.EnrollmentID, Status: status, Resources: resources, PolicyStatus: policy, SentAt: time.Now().UTC()}
			if status.CapabilityReport != nil {
				heartbeat.Hostname = status.CapabilityReport.Platform.Hostname
			}
			if err := client.Heartbeat(ctx, heartbeat); err != nil {
				s.managedError("heartbeat", "central heartbeat failed")
			} else {
				s.managedContact()
				s.managedError("heartbeat", "")
			}
		} else if !errors.Is(err, storage.ErrNotFound) {
			s.managedError("heartbeat", "stored central identity is invalid")
		}
		if !s.waitManagedHeartbeat(ctx, interval) {
			return
		}
	}
}

func (s *Service) waitManagedHeartbeat(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
	case <-s.agentConfigurationHeartbeat:
	}
	return true
}

func (s *Service) managedResources(ctx context.Context) json.RawMessage {
	snapshot, err := s.Resources(ctx)
	if err != nil {
		return json.RawMessage(`{"errors":["resource sampling failed"]}`)
	}
	return encodeManagedResources(snapshot)
}

func encodeManagedResources(snapshot hostmetrics.Snapshot) json.RawMessage {
	snapshot.Errors = append([]string(nil), snapshot.Errors...)
	// Reserve room for agent/capability status inside the central 512 KiB
	// heartbeat limit. ProcessCount still reports the full observed population.
	for {
		raw, err := json.Marshal(snapshot)
		if err != nil {
			return json.RawMessage(`{"errors":["resource encoding failed"]}`)
		}
		if len(raw) <= 384<<10 {
			return raw
		}
		if len(snapshot.Processes) == 0 {
			return json.RawMessage(`{"errors":["resource summary exceeds transport budget"]}`)
		}
		snapshot.Processes = snapshot.Processes[:len(snapshot.Processes)/2]
		if len(snapshot.Errors) == 0 || snapshot.Errors[len(snapshot.Errors)-1] != "process list truncated for central transport budget" {
			snapshot.Errors = append(snapshot.Errors, "process list truncated for central transport budget")
		}
	}
}

func (s *Service) managedPolicyLoop(ctx context.Context) {
	for {
		s.refreshPolicyExpiry(time.Now().UTC())
		client, state, err := s.managedConnection(ctx)
		if err == nil {
			signed, err := client.Policy(ctx)
			if err != nil {
				s.managedError("policy", "central policy polling failed")
			} else {
				s.managedContact()
				s.managedError("policy", "")
				if signed != nil {
					if err := s.applyManagedPolicy(ctx, *signed, state, time.Now().UTC(), false); err != nil {
						s.managedPolicyError(err)
					}
				}
			}
		}
		if !managedWait(ctx, 15*time.Second) {
			return
		}
	}
}

func (s *Service) managedPolicyError(err error) {
	s.managedRuntime.mu.Lock()
	s.managedRuntime.status.Policy.Result = "rejected"
	s.managedRuntime.status.Policy.Error = err.Error()
	s.managedRuntime.mu.Unlock()
}
