package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const maxTetragonStderrBytes = 64 << 10
const maxTetragonEventBytes = 4 << 20
const maxTetragonConsecutiveParseErrors = 16
const maxTetragonAncestors = 64

// CommandSpec is deliberately not a command line string. Path and arguments
// are passed directly to execve, so event data can never be interpreted by a
// shell.
type CommandSpec struct {
	Path string
	Args []string
	Env  []string
	Dir  string
}

func (s CommandSpec) validate() error {
	if strings.TrimSpace(s.Path) == "" {
		return errors.New("command path is required")
	}
	if strings.IndexByte(s.Path, 0) >= 0 {
		return errors.New("command path contains NUL")
	}
	for _, arg := range s.Args {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("command argument contains NUL")
		}
	}
	return nil
}

// TetragonJSON consumes the JSON stream printed by a pinned tetra client (or
// an equivalent event-only command). A Unix-domain gRPC endpoint should be
// supplied in Args; the collector never exposes or proxies Tetragon's control
// API.
type TetragonJSON struct {
	command  CommandSpec
	metadata Metadata
	health   *healthState

	mu     sync.Mutex
	cancel context.CancelFunc
}

func NewTetragonJSON(command CommandSpec, metadata Metadata) *TetragonJSON {
	return &TetragonJSON{command: command, metadata: metadata, health: newHealthState("tetragon-json")}
}

func (c *TetragonJSON) Name() string { return "tetragon-json" }

func (c *TetragonJSON) Probe(ctx context.Context) ProbeResult {
	report := ProbeResult{
		Name: c.Name(),
		Capabilities: map[string]model.CapabilityState{
			"process_exec":    model.CapabilitySupported,
			"process_exit":    model.CapabilitySupported,
			"process_lineage": model.CapabilitySupported,
		},
		Evidence: map[string]string{"command": c.command.Path},
	}
	if err := c.command.validate(); err != nil {
		report.Reason = err.Error()
		return report
	}
	resolved, err := exec.LookPath(c.command.Path)
	if err != nil {
		report.Reason = err.Error()
		return report
	}
	if err := ctx.Err(); err != nil {
		report.Reason = err.Error()
		return report
	}
	report.Available, report.Usable = true, true
	report.Evidence["resolved_command"] = resolved
	return report
}

func (c *TetragonJSON) Run(ctx context.Context, sink EventSink) error {
	if sink == nil {
		return errors.New("tetragon collector requires an event sink")
	}
	if err := c.command.validate(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		c.cancel = nil
		c.mu.Unlock()
	}()

	// No shell is involved: executable and arguments are separate parameters.
	command := exec.CommandContext(runCtx, c.command.Path, c.command.Args...)
	if len(c.command.Env) != 0 {
		command.Env = append(os.Environ(), c.command.Env...)
	}
	command.Dir = c.command.Dir
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create tetragon stdout pipe: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("create tetragon stderr pipe: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start tetragon event command: %w", err)
	}
	c.health.update(func(h *HealthSnapshot) { h.Running = true })
	defer c.health.update(func(h *HealthSnapshot) { h.Running = false })

	stderrResult := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(io.LimitReader(stderr, maxTetragonStderrBytes))
		// Continue draining after the diagnostic capture limit. Otherwise a
		// noisy child can fill the pipe and deadlock command.Wait.
		_, _ = io.Copy(io.Discard, stderr)
		stderrResult <- strings.TrimSpace(string(data))
	}()
	consumeErr := c.consume(runCtx, stdout, sink)
	if consumeErr != nil {
		cancel()
	}
	waitErr := command.Wait()
	stderrText := <-stderrResult
	if consumeErr != nil {
		return consumeErr
	}
	if waitErr != nil && ctx.Err() == nil {
		if stderrText != "" {
			return fmt.Errorf("tetragon event command: %w: %s", waitErr, stderrText)
		}
		return fmt.Errorf("tetragon event command: %w", waitErr)
	}
	return ctx.Err()
}

func (c *TetragonJSON) consume(ctx context.Context, reader io.Reader, sink EventSink) error {
	// tetra emits JSONL. Scanner provides a hard per-event allocation bound;
	// accepting an unbounded json.Decoder here would let a compromised source
	// exhaust agent memory with a single value.
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxTetragonEventBytes)
	consecutiveParseErrors := 0
	for scanner.Scan() {
		raw := json.RawMessage(strings.TrimSpace(scanner.Text()))
		if len(raw) == 0 {
			continue
		}
		c.health.update(func(h *HealthSnapshot) { h.EventsReceived++ })
		event, err := NormalizeTetragonJSON(raw, time.Now().UTC(), c.metadata)
		if errors.Is(err, ErrUnsupportedEvent) {
			consecutiveParseErrors = 0
			c.health.update(func(h *HealthSnapshot) { h.EventsDropped++ })
			continue
		}
		if err != nil {
			c.health.update(func(h *HealthSnapshot) { h.ParseErrors++; h.LastError = err.Error() })
			consecutiveParseErrors++
			if consecutiveParseErrors >= maxTetragonConsecutiveParseErrors {
				return fmt.Errorf("too many consecutive malformed Tetragon events: %w", err)
			}
			continue
		}
		consecutiveParseErrors = 0
		if err := sink.Submit(ctx, event); err != nil {
			c.health.update(func(h *HealthSnapshot) { h.LastError = err.Error() })
			return fmt.Errorf("submit tetragon event: %w", err)
		}
		c.health.update(func(h *HealthSnapshot) { h.EventsEmitted++; h.LastEventAt = event.EventTime })
	}
	if err := scanner.Err(); err != nil {
		c.health.update(func(h *HealthSnapshot) { h.ParseErrors++; h.LastError = err.Error() })
		return fmt.Errorf("scan tetragon JSON stream: %w", err)
	}
	return nil
}

func (c *TetragonJSON) Health() HealthSnapshot { return c.health.get() }

func (c *TetragonJSON) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

type tetragonEnvelope struct {
	ProcessExec *tetragonProcessExec `json:"process_exec"`
	ProcessExit *tetragonProcessExit `json:"process_exit"`
	Time        time.Time            `json:"time"`
}

type tetragonProcessExec struct {
	Process   tetragonProcess   `json:"process"`
	Parent    *tetragonProcess  `json:"parent"`
	Ancestors []tetragonProcess `json:"ancestors"`
}

type tetragonProcessExit struct {
	Process   tetragonProcess   `json:"process"`
	Parent    *tetragonProcess  `json:"parent"`
	Signal    string            `json:"signal"`
	Status    uint32            `json:"status"`
	Time      time.Time         `json:"time"`
	Ancestors []tetragonProcess `json:"ancestors"`
}

type tetragonProcess struct {
	ExecID             string               `json:"exec_id"`
	ParentExecID       string               `json:"parent_exec_id"`
	PID                int                  `json:"pid"`
	UID                *uint32              `json:"uid"`
	CWD                string               `json:"cwd"`
	Binary             string               `json:"binary"`
	Arguments          string               `json:"arguments"`
	StartTime          time.Time            `json:"start_time"`
	ProcessCredentials *tetragonCredentials `json:"process_credentials"`
}

type tetragonCredentials struct {
	UID  *uint32 `json:"uid"`
	EUID *uint32 `json:"euid"`
	GID  *uint32 `json:"gid"`
	EGID *uint32 `json:"egid"`
}

func NormalizeTetragonJSON(raw []byte, ingestTime time.Time, metadata Metadata) (model.Event, error) {
	var envelope tetragonEnvelope
	if err := decodeSingleJSON(raw, &envelope); err != nil {
		return model.Event{}, fmt.Errorf("decode tetragon event: %w", err)
	}
	event := model.Event{
		SchemaVersion: model.SchemaVersion,
		Source:        "tetragon",
		StreamID:      "process",
		IngestTime:    ingestTime.UTC(),
		Completeness:  model.CompletenessComplete,
		RawJSON:       append(json.RawMessage(nil), raw...),
	}
	metadata.apply(&event)

	var source tetragonProcess
	var parent *tetragonProcess
	var ancestors []tetragonProcess
	switch {
	case envelope.ProcessExec != nil:
		event.Type = "process.exec"
		source, parent = envelope.ProcessExec.Process, envelope.ProcessExec.Parent
		ancestors = envelope.ProcessExec.Ancestors
		event.EventTime = envelope.Time.UTC()
		if event.EventTime.IsZero() {
			event.EventTime = source.StartTime.UTC()
		}
		if source.ExecID != "" {
			event.SourceEventID = "exec:" + source.ExecID
		}
	case envelope.ProcessExit != nil:
		event.Type = "process.exit"
		source, parent = envelope.ProcessExit.Process, envelope.ProcessExit.Parent
		ancestors = envelope.ProcessExit.Ancestors
		event.EventTime = envelope.ProcessExit.Time.UTC()
		if event.EventTime.IsZero() {
			event.EventTime = envelope.Time.UTC()
		}
		if source.ExecID != "" && !event.EventTime.IsZero() {
			event.SourceEventID = fmt.Sprintf("exit:%s:%s", source.ExecID, event.EventTime.Format(time.RFC3339Nano))
		}
	default:
		return model.Event{}, ErrUnsupportedEvent
	}
	if event.SourceEventID != "" {
		event.ID = identity.SourceEventID(event.BootID, event.Source, event.Type, event.SourceEventID)
	}

	event.Process = tetragonToProcess(source, event.EventTime)
	parentConsistent := true
	if source.ParentExecID != "" {
		event.Process.ParentKey = identity.ProcessKey(event.BootID, model.Process{ExecID: source.ParentExecID}, event.EventTime)
	}
	if parent != nil && parent.PID > 0 {
		parentProcess := tetragonToProcess(*parent, event.EventTime)
		event.Process.PPID = parentProcess.PID
		if parent.ExecID != "" {
			if source.ParentExecID == "" || source.ParentExecID == parent.ExecID {
				event.Process.ParentKey = identity.ProcessKey(event.BootID, parentProcess, event.EventTime)
				event.Process.Complete = true
			} else {
				// Contradictory identities must not attach a process to a parent
				// selected only by a potentially reused PID.
				event.Process.PPID = -1
				parentConsistent = false
				markPartial(&event, "process.parent_identity")
			}
		}
	}
	if source.ExecID != "" && event.Process.ParentKey != "" && parentConsistent {
		event.Process.LineageConfidence = model.LineageVerified
	}
	if event.Type == "process.exit" && !event.EventTime.IsZero() {
		at := event.EventTime
		event.Process.ExitedAt = &at
	}
	event.Process.Key = identity.ProcessKey(event.BootID, event.Process, event.EventTime)
	contextSources := make([]tetragonProcess, 0, maxTetragonAncestors)
	if parent != nil {
		contextSources = append(contextSources, *parent)
	}
	if len(ancestors) > maxTetragonAncestors-len(contextSources) {
		ancestors = ancestors[:maxTetragonAncestors-len(contextSources)]
		event.TruncatedFields = append(event.TruncatedFields, "ancestors")
		event.Completeness = model.CompletenessPartial
	}
	contextSources = append(contextSources, ancestors...)
	seen := map[string]struct{}{source.ExecID: {}}
	for _, contextSource := range contextSources {
		if contextSource.PID < 1 || contextSource.ExecID == "" {
			continue
		}
		if _, duplicate := seen[contextSource.ExecID]; duplicate {
			continue
		}
		seen[contextSource.ExecID] = struct{}{}
		contextProcess := tetragonToProcess(contextSource, event.EventTime)
		contextProcess.Key = identity.ProcessKey(event.BootID, contextProcess, event.EventTime)
		if contextSource.ParentExecID != "" {
			contextProcess.ParentKey = identity.ProcessKey(event.BootID, model.Process{ExecID: contextSource.ParentExecID}, event.EventTime)
			contextProcess.LineageConfidence = model.LineageVerified
		}
		event.Ancestors = append(event.Ancestors, contextProcess)
	}
	if event.EventTime.IsZero() {
		markPartial(&event, "event_time")
	}
	if source.ExecID == "" {
		markPartial(&event, "process.exec_id")
	}
	if source.Binary == "" {
		markPartial(&event, "process.exe")
	}
	if event.Process.EUID == model.UnknownCredentialID {
		markPartial(&event, "process.euid")
	}
	if source.Arguments != "" {
		// Tetragon exports a flattened argument string, so exact argv boundaries
		// cannot be reconstructed without potentially changing evidence.
		markPartial(&event, "process.argv_exact")
	}
	return event, nil
}

func tetragonToProcess(source tetragonProcess, observedAt time.Time) model.Process {
	process := model.Process{
		ExecID:            source.ExecID,
		PID:               source.PID,
		PPID:              -1,
		StartTime:         source.StartTime.UTC(),
		Exe:               source.Binary,
		UID:               model.UnknownCredentialID,
		EUID:              credentialID(source.UID),
		GID:               model.UnknownCredentialID,
		EGID:              model.UnknownCredentialID,
		CWD:               source.CWD,
		LineageConfidence: model.LineageUnknown,
		FirstSeen:         observedAt,
		LastSeen:          observedAt,
	}
	if source.Binary != "" {
		process.Argv = []string{source.Binary}
	}
	// Tetragon's top-level uid is the effective UID, not the real UID.
	// The optional process_credentials object supplies the complete set.
	if credentials := source.ProcessCredentials; credentials != nil {
		process.UID = credentialID(credentials.UID)
		process.GID = credentialID(credentials.GID)
		process.EGID = credentialID(credentials.EGID)
		if credentials.EUID != nil {
			process.EUID = credentialID(credentials.EUID)
		}
	}
	return process
}

func credentialID(value *uint32) int64 {
	if value == nil {
		return model.UnknownCredentialID
	}
	return int64(*value)
}

func markPartial(event *model.Event, field string) {
	event.Completeness = model.CompletenessPartial
	event.MissingFields = append(event.MissingFields, field)
}
