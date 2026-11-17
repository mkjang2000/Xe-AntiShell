// Package collector adapts host event sources to the collector-independent
// domain model. Collectors never invoke a shell and must report data loss or
// incomplete source records instead of silently fabricating fields.
package collector

import (
	"context"
	"errors"
	"sync"
	"time"

	"xe-antishell/internal/model"
)

var ErrUnsupportedEvent = errors.New("unsupported collector event")

type ProbeResult struct {
	Name         string                           `json:"name"`
	Available    bool                             `json:"available"`
	Usable       bool                             `json:"usable"`
	Capabilities map[string]model.CapabilityState `json:"capabilities,omitempty"`
	Evidence     map[string]string                `json:"evidence,omitempty"`
	Limitations  []string                         `json:"limitations,omitempty"`
	Reason       string                           `json:"reason,omitempty"`
}

type HealthSnapshot struct {
	Name           string    `json:"name"`
	Running        bool      `json:"running"`
	EventsReceived uint64    `json:"events_received"`
	EventsEmitted  uint64    `json:"events_emitted"`
	EventsDropped  uint64    `json:"events_dropped"`
	ParseErrors    uint64    `json:"parse_errors"`
	LastEventAt    time.Time `json:"last_event_at,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
}

type Collector interface {
	Name() string
	Probe(context.Context) ProbeResult
	Run(context.Context, EventSink) error
	Health() HealthSnapshot
	Close() error
}

type EventSink interface {
	Submit(context.Context, model.Event) error
}

type SinkFunc func(context.Context, model.Event) error

func (f SinkFunc) Submit(ctx context.Context, event model.Event) error {
	return f(ctx, event)
}

// Metadata supplies the host-scoped fields that a source event cannot know.
// Sequence allocation remains the owning pipeline's responsibility.
type Metadata struct {
	HostID   string
	BootID   string
	StreamID string
}

func (m Metadata) apply(event *model.Event) {
	event.HostID = m.HostID
	event.BootID = m.BootID
	if event.StreamID == "" {
		event.StreamID = m.StreamID
	}
}

type healthState struct {
	mu       sync.RWMutex
	snapshot HealthSnapshot
}

func newHealthState(name string) *healthState {
	return &healthState{snapshot: HealthSnapshot{Name: name}}
}

func (h *healthState) get() HealthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.snapshot
}

func (h *healthState) update(fn func(*HealthSnapshot)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn(&h.snapshot)
}
