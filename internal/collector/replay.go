package collector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"xe-antishell/internal/model"
)

const defaultReplayMaxLineBytes = 4 << 20

// ReplayJSONL replays one normalized model.Event per line. It is intended for
// deterministic tests and offline troubleshooting, not for following a live
// file that may be rotated.
type ReplayJSONL struct {
	path         string
	reader       io.Reader
	maxLineBytes int
	metadata     Metadata
	health       *healthState
}

func NewReplayJSONL(path string, metadata Metadata) *ReplayJSONL {
	return &ReplayJSONL{
		path:         path,
		maxLineBytes: defaultReplayMaxLineBytes,
		metadata:     metadata,
		health:       newHealthState("replay-jsonl"),
	}
}

func NewReplayJSONLReader(name string, reader io.Reader, metadata Metadata) *ReplayJSONL {
	return &ReplayJSONL{
		path:         name,
		reader:       reader,
		maxLineBytes: defaultReplayMaxLineBytes,
		metadata:     metadata,
		health:       newHealthState("replay-jsonl"),
	}
}

func (c *ReplayJSONL) Name() string { return "replay-jsonl" }

func (c *ReplayJSONL) Probe(_ context.Context) ProbeResult {
	report := ProbeResult{
		Name:         c.Name(),
		Capabilities: map[string]model.CapabilityState{"event_replay": model.CapabilitySupported},
		Evidence:     map[string]string{"source": c.path},
	}
	if c.reader != nil {
		report.Available, report.Usable = true, true
		return report
	}
	info, err := os.Stat(c.path)
	if err != nil {
		report.Reason = err.Error()
		return report
	}
	report.Available, report.Usable = !info.IsDir(), !info.IsDir()
	if info.IsDir() {
		report.Reason = "replay source is a directory"
	}
	return report
}

func (c *ReplayJSONL) Run(ctx context.Context, sink EventSink) error {
	if sink == nil {
		return errors.New("replay collector requires an event sink")
	}
	reader := c.reader
	var closer io.Closer
	if reader == nil {
		file, err := os.Open(c.path)
		if err != nil {
			return fmt.Errorf("open replay source: %w", err)
		}
		reader, closer = file, file
	}
	if closer != nil {
		defer closer.Close()
	}

	c.health.update(func(h *HealthSnapshot) { h.Running = true })
	defer c.health.update(func(h *HealthSnapshot) { h.Running = false })

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), c.maxLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		c.health.update(func(h *HealthSnapshot) { h.EventsReceived++ })
		var event model.Event
		if err := decodeSingleJSON([]byte(line), &event); err != nil {
			c.health.update(func(h *HealthSnapshot) { h.ParseErrors++; h.LastError = err.Error() })
			return fmt.Errorf("decode replay line %d: %w", lineNumber, err)
		}
		if event.SchemaVersion == "" {
			event.SchemaVersion = model.SchemaVersion
		}
		c.metadata.apply(&event)
		if err := sink.Submit(ctx, event); err != nil {
			c.health.update(func(h *HealthSnapshot) { h.LastError = err.Error() })
			return fmt.Errorf("submit replay line %d: %w", lineNumber, err)
		}
		c.health.update(func(h *HealthSnapshot) { h.EventsEmitted++; h.LastEventAt = event.EventTime })
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan replay source: %w", err)
	}
	return nil
}

func (c *ReplayJSONL) Health() HealthSnapshot { return c.health.get() }
func (c *ReplayJSONL) Close() error           { return nil }
