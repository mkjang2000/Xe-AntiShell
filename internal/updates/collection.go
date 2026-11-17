package updates

import (
	"context"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/localapi"
	"xe-antishell/internal/model"
)

type CollectionBaseline struct {
	Collector         string    `json:"collector"`
	Active            bool      `json:"active"`
	PriorExecVerified bool      `json:"prior_exec_verified"`
	DaemonStartedAt   time.Time `json:"daemon_started_at"`
	CapturedAt        time.Time `json:"captured_at"`
}

func collectionActive(status model.AgentStatus) bool {
	if status.Collector != "tetragon-json" && status.Collector != "audit-dispatcher" {
		return false
	}
	stream := status.CollectorHealth
	if stream == nil || stream.Name != status.Collector || !stream.Running || stream.LastError != "" || status.CapabilityReport == nil {
		return false
	}
	collectorKey := "collector.tetragon"
	if status.Collector == "audit-dispatcher" {
		collectorKey = "collector.audit"
	}
	for _, name := range []string{collectorKey, "observation.process_exec"} {
		value := status.CapabilityReport.Capabilities[name]
		if value.Implementation != "implemented" || value.RuntimeState != "active" || value.VerifiedAt == nil || value.VerifiedAt.Before(status.StartedAt) {
			return false
		}
	}
	return !status.StartedAt.IsZero()
}

func BaselineFromStatus(status model.AgentStatus, now time.Time) CollectionBaseline {
	known := status.Collector == "tetragon-json" || status.Collector == "audit-dispatcher"
	running := status.CollectorHealth != nil && status.CollectorHealth.Running
	return CollectionBaseline{Collector: status.Collector, Active: known && running, PriorExecVerified: collectionActive(status), DaemonStartedAt: status.StartedAt, CapturedAt: now.UTC()}
}

func CaptureCollection(ctx context.Context) (CollectionBaseline, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, err := localapi.NewClient(SocketPath).Status(bounded)
	if err != nil || status.StartedAt.IsZero() {
		return CollectionBaseline{}, errors.New("service_unavailable")
	}
	return BaselineFromStatus(status, time.Now()), nil
}

func CollectionMatches(baseline CollectionBaseline, status model.AgentStatus) bool {
	return baseline.Active && status.Collector == baseline.Collector && status.StartedAt.After(baseline.DaemonStartedAt) && collectionActive(status)
}

func VerifyCollection(ctx context.Context, baseline CollectionBaseline) bool {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, err := localapi.NewClient(SocketPath).Status(bounded)
	return err == nil && CollectionMatches(baseline, status)
}

func (m *Manager) probeCollection(ctx context.Context, baseline CollectionBaseline) {
	// These are actual harmless execs. No synthetic telemetry is injected.
	_, _ = m.Runner.Run(ctx, "/usr/bin/true")
	if baseline.Collector == "audit-dispatcher" {
		_, _ = m.Runner.Run(ctx, "/bin/sh", "-c", "/usr/bin/true")
	}
}

func (m *Manager) verifyOutcome(ctx context.Context, job *Job, installed *managed.RPMPackage, failureCode string) error {
	plan := job.Plan.Plan
	if installed == nil || *installed != plan.Release.Package {
		return m.transition(plan.JobID, "failed", failureCode, m.running(ctx), installed)
	}
	wait := m.HealthTimeout
	if wait <= 0 {
		wait = 60 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var lastProbe time.Time
	running := "unknown"
	healthy := false
	for {
		running = m.running(bounded)
		healthy = m.Healthy != nil && m.Healthy(bounded, plan)
		if healthy {
			check := "not_applicable"
			if job.Collection.Active {
				check = "verified"
				if m.VerifyCollection == nil || !m.VerifyCollection(bounded, job.Collection) {
					check = "failed"
					if bounded.Err() == nil && time.Since(lastProbe) >= 2*time.Second {
						m.probeCollection(bounded, job.Collection)
						lastProbe = time.Now()
					}
				}
			}
			if check != "failed" {
				actual, err := QueryPackage(bounded, m.Runner, "")
				if err != nil {
					return m.transition(plan.JobID, "failed", "verification_failed", running, nil, check)
				}
				if actual != plan.Release.Package {
					return m.transition(plan.JobID, "failed", "precondition_changed", running, &actual, check)
				}
				return m.transition(plan.JobID, "succeeded", "", PackageVersion(actual), &actual, check)
			}
		}
		select {
		case <-bounded.Done():
			code, check := failureCode, "not_applicable"
			if job.Collection.Active {
				check = "failed"
				if healthy {
					code = "collection_check_failed"
				}
			}
			if ctx.Err() != nil {
				code = "interrupted"
			}
			return m.transition(plan.JobID, "failed", code, running, installed, check)
		case <-time.After(time.Second):
		}
	}
}
