package agent

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/hostmetrics"
)

type managedResourceSample struct {
	data json.RawMessage
}

func samplingManaged(configuration managed.AgentConfiguration) bool {
	return configuration.Set.Monitoring != nil || slices.Contains(configuration.Inherit, managed.AgentConfigSamplingKey)
}

func (s *Service) heartbeatInterval(monitoring managed.MonitoringPolicy, configuration managed.AgentConfiguration) int {
	if samplingManaged(configuration) {
		return independentHeartbeatSeconds
	}
	return monitoring.SampleIntervalSeconds
}

func agentSampleInterval(monitoring managed.MonitoringPolicy, configuration managed.AgentConfiguration) int {
	if configuration.Set.Monitoring != nil {
		return configuration.Set.Monitoring.SampleIntervalSeconds
	}
	if samplingManaged(configuration) {
		return independentHeartbeatSeconds
	}
	return monitoring.SampleIntervalSeconds
}

func (s *Service) agentConfigurationEffective(configuration managed.AgentConfiguration) managed.AgentConfigurationEffective {
	monitoring := s.currentMonitoring()
	effective := managed.AgentConfigurationEffective{
		SampleIntervalSeconds:          agentSampleInterval(monitoring, configuration),
		HeartbeatIntervalSeconds:       s.heartbeatInterval(monitoring, configuration),
		ObservationHistoryMinutes:      s.observationHistoryMinutesFor(configuration),
		RetentionDays:                  s.config.Limits.RetentionDays,
		LocalObservationHistoryMinutes: s.config.Limits.ObservationHistoryMinutes,
		LocalRetentionDays:             s.config.Limits.RetentionDays,
		MaxObservationHistoryMinutes:   s.config.AgentConfiguration.MaxObservationHistoryMinutes,
		PanelAccess:                    "allow",
		Sources: map[string]string{
			managed.AgentConfigSamplingKey:  "local",
			managed.AgentConfigRetentionKey: "local",
			managed.AgentConfigPanelKey:     "local",
		},
	}
	if configuration.Set.Monitoring != nil {
		effective.Sources[managed.AgentConfigSamplingKey] = "central"
	} else if !samplingManaged(configuration) {
		if current := s.detectionState.Load(); current != nil && current.policy != nil {
			effective.Sources[managed.AgentConfigSamplingKey] = "legacy_policy"
		}
	}
	if limit := s.config.AgentConfiguration.MaxObservationHistoryMinutes; configuration.Set.Retention != nil && configuration.Set.Retention.ObservationHistoryMinutes <= limit {
		effective.Sources[managed.AgentConfigRetentionKey] = "central"
	}
	if configuration.Set.LocalPanel != nil {
		effective.Sources[managed.AgentConfigPanelKey] = "central"
		effective.PanelAccess = configuration.Set.LocalPanel.Access
	}
	return effective
}

func (s *Service) managedResourceSamplerLoop(ctx context.Context) {
	sampler := hostmetrics.New("/proc", "/sys")
	var last time.Time
	for {
		configuration := s.approvedAgentConfiguration()
		monitoring := s.currentMonitoring()
		if !samplingManaged(configuration) || !monitoring.Enabled {
			s.managedResourceCache.Store(nil)
			last = time.Time{}
		} else if time.Since(last) >= time.Duration(agentSampleInterval(monitoring, configuration))*time.Second {
			data := encodeManagedResources(sampler.Sample(ctx, monitoring.ProcessLimit))
			if ctx.Err() != nil {
				return
			}
			s.managedResourceCache.Store(&managedResourceSample{data: data})
			last = time.Now()
		}
		if !managedWait(ctx, time.Second) {
			return
		}
	}
}
