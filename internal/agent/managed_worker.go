package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/storage"
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
	for _, worker := range []func(context.Context){s.managedDeliveryLoop, s.managedHeartbeatLoop, s.managedPolicyLoop} {
		s.producerWG.Add(1)
		go func(run func(context.Context)) { defer s.producerWG.Done(); run(ctx) }(worker)
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
	backoff := time.Second
	for {
		s.managedRuntime.senderMu.Lock()
		_, err := s.deliverManagedBatch(ctx)
		s.managedRuntime.senderMu.Unlock()
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		} else {
			backoff = time.Second
		}
		if !managedWait(ctx, backoff) {
			return
		}
	}
}

func (s *Service) managedHeartbeatLoop(ctx context.Context) {
	for {
		interval := time.Second * time.Duration(s.currentMonitoring().SampleIntervalSeconds)
		client, state, err := s.managedConnection(ctx)
		if err == nil {
			status, _ := s.Status(ctx)
			s.managedRuntime.mu.RLock()
			policy := s.managedRuntime.status.Policy
			s.managedRuntime.mu.RUnlock()
			var resources json.RawMessage
			if s.currentMonitoring().Enabled {
				resources = s.managedResources(ctx)
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
		if !managedWait(ctx, interval) {
			return
		}
	}
}

func (s *Service) managedResources(ctx context.Context) json.RawMessage {
	snapshot, err := s.Resources(ctx)
	if err != nil {
		return json.RawMessage(`{"errors":["resource sampling failed"]}`)
	}
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
