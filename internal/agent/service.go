// Package agent wires capability discovery, collection, persistence, lineage,
// detection, and the local API backend.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"xe-antishell/internal/buildinfo"
	"xe-antishell/internal/capability"
	"xe-antishell/internal/collector"
	"xe-antishell/internal/config"
	"xe-antishell/internal/detection"
	"xe-antishell/internal/hostmetrics"
	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
	"xe-antishell/internal/procfs"
	"xe-antishell/internal/storage"
	"xe-antishell/internal/updates"
)

var Version = buildinfo.RunningVersion()

var (
	ErrInvalidEvent    = errors.New("invalid normalized event")
	ErrServiceStopping = errors.New("agent service is not accepting events")
)

const auditShutdownFlushTimeout = 2 * time.Second
const retentionInterval = 6 * time.Hour
const retentionBatchSize = 1000
const maxRetentionBatchesPerRun = 10

type CapabilityProber interface {
	Probe(context.Context) (model.CapabilityReport, error)
}

// ProcessSource supplies a live, boot-scoped process snapshot and a best-effort
// service lookup for new exec events. The interface is public so deployments
// and tests can substitute an equivalent procfs reader without weakening the
// agent's collector boundary.
type ProcessSource interface {
	Snapshot(context.Context, string) ([]model.Process, error)
	OriginService(context.Context, int) (string, error)
}

type Service struct {
	config         config.Config
	store          *storage.Store
	prober         CapabilityProber
	processSource  ProcessSource
	lineage        *lineage.Tracker
	metrics        *hostmetrics.Sampler
	detector       *detection.Engine
	detectionState atomic.Pointer[detectionState]
	managedRuntime *managedRuntime
	updateManager  *updates.Manager

	eventQueue chan model.Event
	sequence   atomic.Uint64
	dropped    atomic.Uint64
	parseErrs  atomic.Uint64

	statusMu        sync.RWMutex
	status          model.AgentStatus
	report          model.CapabilityReport
	runtimeEvidence map[string]sourceRuntimeEvidence

	collectorMu sync.Mutex
	collector   collector.Collector
	cancel      context.CancelFunc
	producerWG  sync.WaitGroup
	processorWG sync.WaitGroup

	submitMu  sync.Mutex
	submitWG  sync.WaitGroup
	accepting bool

	lifecycleMu   sync.Mutex
	started       bool
	stopping      bool
	stopped       bool
	shutdownDone  chan struct{}
	processorStop chan struct{}

	auditMu        sync.Mutex
	auditAssembler *collector.AuditAssembler
	bootstrapErr   error
}

func New(cfg config.Config, store *storage.Store, prober CapabilityProber) (*Service, error) {
	return NewWithProcessSource(cfg, store, prober, procfs.New("/proc"))
}

// NewWithProcessSource constructs an agent with an explicit live-process
// source. Production callers normally use New; this form keeps procfs behavior
// deterministic in tests and alternative Linux mount namespaces.
func NewWithProcessSource(cfg config.Config, store *storage.Store, prober CapabilityProber, processSource ProcessSource) (*Service, error) {
	if store == nil {
		return nil, errors.New("agent requires a storage backend")
	}
	if processSource == nil {
		return nil, errors.New("agent requires a live process source")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate agent configuration: %w", err)
	}
	if prober == nil {
		defaultProber := capability.NewProber()
		defaultProber.ConfiguredTetraCommand = cfg.Collector.Tetragon.Command
		prober = defaultProber
	}
	service := &Service{
		config:        cfg,
		store:         store,
		prober:        prober,
		processSource: processSource,
		lineage:       lineage.New(),
		metrics:       hostmetrics.New("/proc", "/sys"),
		detector: detection.NewWithOptions(detection.Options{
			WebExecutables:       cfg.Detection.WebExecutables,
			WebServices:          cfg.Detection.WebServices,
			Shells:               cfg.Detection.Shells,
			AllowedPairs:         cfg.Detection.AllowedPairs,
			ExtendedProcessRules: cfg.Detection.ExtendedProcessRules,
		}),
		eventQueue:    make(chan model.Event, cfg.Limits.QueueSize),
		shutdownDone:  make(chan struct{}),
		processorStop: make(chan struct{}),
		status: model.AgentStatus{
			Version:   Version,
			Mode:      model.AgentModeUnsupported,
			Health:    model.HealthStarting,
			StartedAt: time.Now().UTC(),
		},
	}
	service.detectionState.Store(&detectionState{engine: service.detector, enabled: cfg.Detection.Enabled})
	service.managedRuntime = newManagedRuntime()
	service.updateManager = updates.NewManager()
	return service, nil
}

func (s *Service) Start(parent context.Context) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.started || s.stopping {
		return errors.New("agent service is already started")
	}
	if s.stopped {
		return errors.New("agent service cannot be restarted after shutdown")
	}

	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	if _, err := s.RefreshCapabilities(ctx); err != nil {
		cancel()
		return err
	}
	s.statusMu.RLock()
	bootID := s.report.Platform.BootID
	s.statusMu.RUnlock()
	lastSequence, err := s.store.LastSequence(ctx, bootID, "process")
	if err != nil {
		cancel()
		return err
	}
	s.sequence.Store(lastSequence)
	liveProcesses, snapshotErr := s.processSource.Snapshot(ctx, bootID)
	if snapshotErr != nil {
		if ctx.Err() != nil {
			cancel()
			return ctx.Err()
		}
		// Durable process observations are only a fallback. Audit input does
		// not provide exits, so restoring it alongside a successful live
		// snapshot would make long-dead PIDs current again.
		activeProcesses, err := s.store.ListActiveProcesses(ctx, bootID, 100_000)
		if err != nil {
			cancel()
			return err
		}
		s.lineage.Restore(activeProcesses)
		s.bootstrapErr = fmt.Errorf("bootstrap live process lineage: %w", snapshotErr)
	} else {
		s.lineage.Restore(liveProcesses)
	}

	selected, mode, err := s.selectCollector(ctx)
	if err != nil {
		s.setRuntimeState(model.AgentModeError, model.HealthError, "", err)
		cancel()
		return err
	}
	s.collectorMu.Lock()
	s.collector = selected
	s.collectorMu.Unlock()
	selectedName := collectorName(selected, mode)
	health, runtimeErr := initialHealth(mode), error(nil)
	if s.bootstrapErr != nil {
		health, runtimeErr = model.HealthDegraded, s.bootstrapErr
	}
	s.setRuntimeState(mode, health, selectedName, runtimeErr)

	if mode == model.AgentModeDegraded && selectedName == "audit-dispatcher" {
		s.auditMu.Lock()
		s.auditAssembler = collector.NewAuditAssembler(collector.AuditAssemblerOptions{
			MaxBytes:           s.config.Limits.MaxEventBytes,
			Metadata:           s.collectorMetadata(),
			IncludeExecutables: s.config.Collector.Audit.IncludeExecutables,
		})
		s.auditMu.Unlock()
	}
	// Restore the last approved detection scope before any event can be accepted.
	s.startManagedWorkers(ctx)
	s.submitMu.Lock()
	s.accepting = true
	s.submitMu.Unlock()
	s.started = true

	s.processorWG.Add(1)
	go s.processLoop()

	if selected != nil {
		s.producerWG.Add(1)
		go s.runCollector(ctx, selected)
	}
	if mode == model.AgentModeDegraded && selectedName == "audit-dispatcher" {
		s.producerWG.Add(1)
		go s.flushAuditLoop(ctx)
	}
	s.producerWG.Add(1)
	go s.retentionLoop(ctx)
	return nil
}

func initialHealth(mode model.AgentMode) model.Health {
	switch mode {
	case model.AgentModeActive:
		return model.HealthStarting
	case model.AgentModeDegraded:
		return model.HealthDegraded
	case model.AgentModeError:
		return model.HealthError
	default:
		return model.HealthDegraded
	}
}

func collectorName(value collector.Collector, mode model.AgentMode) string {
	if value != nil {
		return value.Name()
	}
	if mode == model.AgentModeDegraded {
		return "audit-dispatcher"
	}
	return ""
}

func (s *Service) selectCollector(ctx context.Context) (collector.Collector, model.AgentMode, error) {
	metadata := s.collectorMetadata()
	switch s.config.Collector.Mode {
	case config.CollectorReplay:
		value := collector.NewReplayJSONL(s.config.Collector.Replay.Path, metadata)
		probe := value.Probe(ctx)
		if !probe.Usable {
			return nil, model.AgentModeError, fmt.Errorf("replay collector is unusable: %s", probe.Reason)
		}
		return value, model.AgentModeActive, nil
	case config.CollectorTetragon:
		value := s.newTetragonCollector(metadata)
		probe := value.Probe(ctx)
		if !probe.Usable {
			return nil, model.AgentModeError, fmt.Errorf("Tetragon collector is unusable: %s", probe.Reason)
		}
		return value, model.AgentModeActive, nil
	case config.CollectorAudit:
		return nil, model.AgentModeDegraded, nil
	case config.CollectorDisabled:
		return nil, model.AgentModeUnsupported, nil
	case config.CollectorAuto:
		capabilityValue := s.capabilityValue(capability.TetragonCapability)
		if capabilityValue.State == model.CapabilityLimited || capabilityValue.State == model.CapabilitySupported {
			value := s.newTetragonCollector(metadata)
			if probe := value.Probe(ctx); probe.Usable {
				return value, model.AgentModeActive, nil
			}
		}
		auditValue := s.capabilityValue(capability.AuditCapability)
		if auditValue.State == model.CapabilityLimited || auditValue.State == model.CapabilitySupported {
			return nil, model.AgentModeDegraded, nil
		}
		return nil, model.AgentModeUnsupported, nil
	default:
		return nil, model.AgentModeError, fmt.Errorf("unsupported collector mode %q", s.config.Collector.Mode)
	}
}

func (s *Service) newTetragonCollector(metadata collector.Metadata) collector.Collector {
	command := s.config.Collector.Tetragon.Command
	if resolved, err := exec.LookPath(command); err == nil {
		command = resolved
	}
	return collector.NewTetragonJSON(collector.CommandSpec{
		Path: command,
		Args: append([]string(nil), s.config.Collector.Tetragon.Args...),
	}, metadata)
}

func (s *Service) collectorMetadata() collector.Metadata {
	s.statusMu.RLock()
	bootID := s.report.Platform.BootID
	hostname := s.report.Platform.Hostname
	s.statusMu.RUnlock()
	hostID := strings.TrimSpace(s.config.Agent.ID)
	if hostID == "" {
		hostID = hostname
	}
	return collector.Metadata{
		HostID:   hostID,
		BootID:   bootID,
		StreamID: "process",
	}
}

func (s *Service) hostID() string {
	if value := strings.TrimSpace(s.config.Agent.ID); value != "" {
		return value
	}
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.report.Platform.Hostname
}

func (s *Service) runCollector(ctx context.Context, value collector.Collector) {
	defer s.producerWG.Done()
	s.markCollectorRunning(value.Name())
	if err := value.Run(ctx, s); err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		s.setRuntimeState(model.AgentModeDegraded, model.HealthError, value.Name(), err)
		return
	}
	if ctx.Err() == nil {
		s.setRuntimeState(model.AgentModeDegraded, model.HealthDegraded, value.Name(), errors.New("collector stream ended"))
	}
}

func (s *Service) Submit(ctx context.Context, event model.Event) error {
	s.submitMu.Lock()
	if !s.accepting {
		s.submitMu.Unlock()
		return ErrServiceStopping
	}
	s.submitWG.Add(1)
	s.submitMu.Unlock()
	defer s.submitWG.Done()

	cloneObservationPayloads(&event)
	event.Process.Argv = append([]string(nil), event.Process.Argv...)
	event.Ancestors = append([]model.Process(nil), event.Ancestors...)
	event.MissingFields = append([]string(nil), event.MissingFields...)
	event.RedactedFields = append([]string(nil), event.RedactedFields...)
	event.TruncatedFields = append([]string(nil), event.TruncatedFields...)
	s.sanitizeEventPrivacy(&event)
	// Apply the default raw-payload privacy boundary before queueing so a noisy
	// source cannot fill the bounded queue with data that will be discarded.
	if len(event.RawJSON) > 0 && !s.config.Privacy.StoreRawEvents {
		event.RawJSON = nil
		event.RedactedFields = appendUnique(event.RedactedFields, "raw_json")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		s.dropped.Add(1)
		s.parseErrs.Add(1)
		s.updateCounters()
		return nil
	}
	if len(encoded) > s.config.Limits.MaxEventBytes {
		s.dropped.Add(1)
		s.parseErrs.Add(1)
		s.updateCounters()
		return nil
	}

	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case s.eventQueue <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		s.dropped.Add(1)
		s.updateCounters()
		return nil
	}
}

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

func (s *Service) processQueuedEvent(event model.Event) {
	if err := s.processEvent(context.Background(), &event); err != nil {
		if errors.Is(err, ErrInvalidEvent) {
			s.dropped.Add(1)
			s.updateCounters()
			return
		}
		s.setRuntimeState(model.AgentModeError, model.HealthError, s.currentCollectorName(), err)
	}
}

func (s *Service) processEvent(ctx context.Context, event *model.Event) error {
	detection := s.detectionState.Load()
	if err := s.normalizeEvent(event); err != nil {
		s.parseErrs.Add(1)
		s.updateCounters()
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	s.recordRuntimeEvent(*event)
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
		if event.Source == "audit" && s.config.Collector.Audit.OnlyDetectionOrigins {
			if _, matched := detection.engine.MatchWebOrigin(*event, s.lineage); !matched {
				return nil
			}
		}
		s.lineage.Observe(event)
		s.recordRuntimeEvent(*event)
	case "process.exec_observation", "file.write", "network.connect":
		if err := s.observeOperationContext(ctx, event); err != nil {
			return err
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
			if previous, err := s.store.GetFinding(ctx, findings[index].ID); err == nil && (previous.ResponseDecision == "sigterm_sent" || previous.ResponseDecision == "refused" || previous.ResponseDecision == "not_repeated") {
				findings[index] = previous
			}
		}
	}
	// Evidence, derived findings, and managed delivery are one durable unit.
	if err := s.store.PersistObservation(ctx, *event, findings); err != nil {
		return err
	}
	if err := s.executeResponses(ctx, *event, findings, detection.policy); err != nil {
		return err
	}
	s.markEventProcessed(event.IngestTime)
	return nil
}

func (s *Service) markEventProcessed(at time.Time) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.LastEventAt = &at
	if s.status.Mode == model.AgentModeActive && s.bootstrapErr == nil {
		s.status.Health = model.HealthHealthy
	} else if s.status.Mode == model.AgentModeDegraded {
		s.status.Health = model.HealthDegraded
	}
	s.status.Dropped = s.dropped.Load()
	s.status.ParseErrors = s.parseErrs.Load()
}

func (s *Service) setRuntimeState(mode model.AgentMode, health model.Health, collectorName string, err error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.Mode = mode
	s.status.Health = health
	s.status.Collector = collectorName
	if err != nil {
		s.status.LastError = err.Error()
	} else {
		s.status.LastError = ""
	}
	s.status.Dropped = s.dropped.Load()
	s.status.ParseErrors = s.parseErrs.Load()
}

func (s *Service) updateCounters() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.Dropped = s.dropped.Load()
	s.status.ParseErrors = s.parseErrs.Load()
}

func (s *Service) currentCollectorName() string {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.status.Collector
}

func (s *Service) markCollectorRunning(name string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if s.status.Mode == model.AgentModeActive && s.status.Collector == name {
		if s.bootstrapErr != nil {
			s.status.Health = model.HealthDegraded
			s.status.LastError = s.bootstrapErr.Error()
		} else {
			s.status.Health = model.HealthHealthy
			s.status.LastError = ""
		}
	}
}

func (s *Service) capabilityValue(name string) model.Capability {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.report.Capabilities[name]
}

func (s *Service) Status(_ context.Context) (model.AgentStatus, error) {
	status, _ := s.runtimeSnapshot()
	return status, nil
}

func (s *Service) Capabilities(_ context.Context) (model.CapabilityReport, error) {
	_, report := s.runtimeSnapshot()
	return report, nil
}

func (s *Service) RefreshCapabilities(ctx context.Context) (model.CapabilityReport, error) {
	report, err := s.prober.Probe(ctx)
	if err != nil {
		return model.CapabilityReport{}, err
	}
	if err := s.store.SaveCapabilityReport(ctx, report); err != nil {
		return model.CapabilityReport{}, err
	}
	s.statusMu.Lock()
	s.report = cloneCapabilityReport(report)
	s.statusMu.Unlock()
	return s.Capabilities(ctx)
}

func (s *Service) ListEvents(ctx context.Context, limit int) ([]model.Event, error) {
	return s.store.ListEvents(ctx, storage.EventFilter{Limit: limit})
}

func (s *Service) ListFindings(ctx context.Context, limit int) ([]model.Finding, error) {
	return s.store.ListFindings(ctx, storage.FindingFilter{Limit: limit})
}

func (s *Service) ProcessTree(ctx context.Context, pid, maxDepth int) ([]model.Process, error) {
	if tree := s.lineage.TreeForPID(pid, maxDepth); len(tree) != 0 {
		return tree, nil
	}
	s.statusMu.RLock()
	bootID := s.report.Platform.BootID
	s.statusMu.RUnlock()
	process, err := s.store.FindLatestProcessByPID(ctx, bootID, pid)
	if err != nil {
		return nil, err
	}
	tree := []model.Process{process}
	seen := map[string]struct{}{process.Key: {}}
	for process.ParentKey != "" && len(tree) < maxDepth {
		if _, duplicate := seen[process.ParentKey]; duplicate {
			break
		}
		seen[process.ParentKey] = struct{}{}
		process, err = s.store.GetProcess(ctx, process.ParentKey)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				break
			}
			return nil, err
		}
		tree = append(tree, process)
	}
	return tree, nil
}

func (s *Service) SubmitAuditLine(ctx context.Context, line []byte) error {
	s.statusMu.RLock()
	auditSelected := s.status.Collector == "audit-dispatcher"
	s.statusMu.RUnlock()
	if !auditSelected || s.auditAssembler == nil {
		return errors.New("audit dispatcher is not the selected process collector")
	}
	s.auditMu.Lock()
	events, err := s.auditAssembler.Feed(string(line), time.Now().UTC())
	s.auditMu.Unlock()
	for _, event := range events {
		if err := s.Submit(ctx, event); err != nil {
			return err
		}
	}
	if err != nil {
		s.parseErrs.Add(1)
		s.updateCounters()
		return err
	}
	return nil
}

func (s *Service) flushAuditLoop(ctx context.Context) {
	defer s.producerWG.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.auditMu.Lock()
			events := s.auditAssembler.FlushAll(time.Now().UTC())
			s.auditMu.Unlock()
			flushCtx, cancel := context.WithTimeout(context.Background(), auditShutdownFlushTimeout)
			for index, event := range events {
				if err := s.Submit(flushCtx, event); err != nil {
					s.dropped.Add(uint64(len(events) - index))
					s.updateCounters()
					break
				}
			}
			cancel()
			return
		case now := <-ticker.C:
			s.auditMu.Lock()
			events := s.auditAssembler.FlushExpired(now.UTC())
			s.auditMu.Unlock()
			for _, event := range events {
				_ = s.Submit(ctx, event)
			}
		}
	}
}

func (s *Service) retentionLoop(ctx context.Context) {
	defer s.producerWG.Done()
	run := func() {
		cutoff := time.Now().UTC().AddDate(0, 0, -s.config.Limits.RetentionDays)
		for batch := 0; batch < maxRetentionBatchesPerRun; batch++ {
			deleted, err := s.store.DeleteEventsBefore(ctx, cutoff, retentionBatchSize)
			if err != nil {
				if ctx.Err() == nil {
					s.recordOperationalError(fmt.Errorf("event retention: %w", err))
				}
				return
			}
			if deleted < retentionBatchSize {
				break
			}
		}
		for batch := 0; batch < maxRetentionBatchesPerRun; batch++ {
			deleted, err := s.store.DeleteProcessesBefore(ctx, cutoff, retentionBatchSize)
			if err != nil {
				if ctx.Err() == nil {
					s.recordOperationalError(fmt.Errorf("process retention: %w", err))
				}
				return
			}
			if deleted < retentionBatchSize {
				break
			}
		}
	}
	run()
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Service) recordOperationalError(err error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if s.status.Mode == model.AgentModeActive {
		s.status.Mode = model.AgentModeDegraded
	}
	s.status.Health = model.HealthDegraded
	s.status.LastError = err.Error()
}

func (s *Service) Shutdown(ctx context.Context) error {
	s.lifecycleMu.Lock()
	if s.stopped || !s.started && !s.stopping {
		s.lifecycleMu.Unlock()
		return nil
	}
	if !s.stopping {
		s.stopping = true
		go s.finishShutdown()
	}
	done := s.shutdownDone
	s.lifecycleMu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) finishShutdown() {
	s.collectorMu.Lock()
	if s.collector != nil {
		_ = s.collector.Close()
	}
	s.collectorMu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}

	// Producers may flush final audit groups into the queue. Keep Submit open
	// until every producer has exited, then wait for in-flight submitters.
	s.producerWG.Wait()
	s.submitMu.Lock()
	s.accepting = false
	s.submitMu.Unlock()
	s.submitWG.Wait()
	close(s.processorStop)
	s.processorWG.Wait()

	s.lifecycleMu.Lock()
	s.started = false
	s.stopping = false
	s.stopped = true
	close(s.shutdownDone)
	s.lifecycleMu.Unlock()
}

// DatabasePath returns the resolved configured path for diagnostics.
func (s *Service) DatabasePath() string { return filepath.Clean(s.config.Agent.DatabasePath) }
