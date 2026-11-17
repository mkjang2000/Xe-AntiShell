// Package lineage maintains the best-known boot-scoped process graph.
package lineage

import (
	"container/list"
	"sync"
	"time"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const DefaultMaxRecords = 50_000

type Tracker struct {
	mu      sync.RWMutex
	byKey   map[string]model.Process
	current map[int]string
	recency *list.List
	entries map[string]*list.Element
	maximum int
}

func New() *Tracker {
	return NewBounded(DefaultMaxRecords)
}

// NewBounded limits retained process context independently of durable evidence
// storage. Exited context is evicted first, then the least recently observed
// live context. Once evicted, ancestry lookups stop at the missing key.
func NewBounded(maximum int) *Tracker {
	if maximum < 1 {
		maximum = DefaultMaxRecords
	}
	return &Tracker{
		byKey:   make(map[string]model.Process),
		current: make(map[int]string),
		recency: list.New(),
		entries: make(map[string]*list.Element),
		maximum: maximum,
	}
}

// Restore seeds durable observations after a daemon restart. For a reused PID,
// the newest non-exited start time becomes current while every process remains
// addressable by its stable key.
func (t *Tracker) Restore(processes []model.Process) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, process := range processes {
		if process.Key == "" || process.PID < 1 {
			continue
		}
		currentKey, exists := t.current[process.PID]
		if process.ExitedAt == nil && (!exists || newerProcess(process, t.byKey[currentKey])) {
			t.current[process.PID] = process.Key
		}
		t.retain(process)
	}
}

// newerProcess provides a deterministic restart-time tie-break for collectors
// such as Linux audit whose event time may have only millisecond precision.
// It is also used for source context, which can arrive after a newer execution.
func newerProcess(candidate, current model.Process) bool {
	if !candidate.StartTime.Equal(current.StartTime) {
		return candidate.StartTime.After(current.StartTime)
	}
	if !candidate.LastSeen.Equal(current.LastSeen) {
		return candidate.LastSeen.After(current.LastSeen)
	}
	return candidate.Key > current.Key
}

// Observe adds or updates the process attached to an event and returns the
// normalized process record. Missing parents stay explicitly incomplete.
func (t *Tracker) Observe(event *model.Event) model.Process {
	t.mu.Lock()
	defer t.mu.Unlock()

	process := event.Process
	if process.Key == "" {
		process.Key = identity.ProcessKey(event.BootID, process, event.EventTime)
	}
	if process.StartTime.IsZero() {
		process.StartTime = event.EventTime
	}
	observedAt := event.IngestTime
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	mergeObservationTimes(&process, observedAt)

	if process.ParentKey == "" && process.PPID > 0 {
		if parentKey, ok := t.current[process.PPID]; ok {
			process.ParentKey = parentKey
			process.Complete = true
			if process.LineageConfidence == "" || process.LineageConfidence == model.LineageUnknown {
				process.LineageConfidence = model.LineageInferred
			}
		}
	}
	if process.OriginService == "" && process.ParentKey != "" {
		if parent, ok := t.byKey[process.ParentKey]; ok {
			process.OriginService = parent.OriginService
		}
	}
	if process.PID == 1 || process.PPID == 0 {
		process.Complete = true
	}
	if process.LineageConfidence == "" {
		if process.ExecID != "" && process.ParentKey != "" {
			process.LineageConfidence = model.LineageVerified
		} else if process.ParentKey != "" {
			process.LineageConfidence = model.LineageInferred
		} else {
			process.LineageConfidence = model.LineageUnknown
		}
	}

	if previous, ok := t.byKey[process.Key]; ok {
		mergeObservationTimes(&process, previous.FirstSeen, previous.LastSeen)
		if process.ParentKey == "" {
			process.ParentKey = previous.ParentKey
		}
	}

	t.current[process.PID] = process.Key
	t.retain(process)
	event.Process = process
	return process
}

// ObserveContext imports a source snapshot without asserting that a new exec
// happened now. A delayed ancestor attached to another event must not revive
// an exited execution or replace a newer execution sharing its PID.
func (t *Tracker) ObserveContext(process model.Process) model.Process {
	t.mu.Lock()
	defer t.mu.Unlock()
	if process.Key == "" || process.PID < 1 {
		return process
	}
	firstSeen, lastSeen := process.FirstSeen, process.LastSeen
	if previous, exists := t.byKey[process.Key]; exists {
		if previous.OriginService == "" {
			previous.OriginService = process.OriginService
		}
		if previous.ParentKey == "" {
			previous.ParentKey = process.ParentKey
		}
		process = previous
	}
	mergeObservationTimes(&process, firstSeen, lastSeen)
	if process.ParentKey != "" {
		if parent, exists := t.byKey[process.ParentKey]; exists {
			if process.OriginService == "" {
				process.OriginService = parent.OriginService
			}
			if process.PPID < 1 {
				process.PPID = parent.PID
			}
			process.Complete = true
		}
	}
	currentKey, exists := t.current[process.PID]
	if process.ExitedAt == nil && (!exists || newerProcess(process, t.byKey[currentKey])) {
		t.current[process.PID] = process.Key
	}
	t.retain(process)
	return process
}

func (t *Tracker) Exit(processKey string, pid int, at time.Time) (model.Process, bool) {
	return t.ExitObserved(processKey, pid, at, at)
}

// ExitObserved preserves the source's exit time separately from the time this
// agent observed its delivery. Delayed exits and wall-clock changes cannot
// reverse the first/last bounds or discard previous observations.
func (t *Tracker) ExitObserved(processKey string, pid int, exitedAt, observedAt time.Time) (model.Process, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if processKey == "" {
		processKey = t.current[pid]
	}
	process, ok := t.byKey[processKey]
	if !ok {
		return model.Process{}, false
	}
	process.ExitedAt = &exitedAt
	mergeObservationTimes(&process, observedAt)
	if t.current[process.PID] == processKey {
		delete(t.current, process.PID)
	}
	t.retain(process)
	return process, true
}

// mergeObservationTimes takes the envelope of actual observation timestamps.
// Legacy context can contain source times and observations can arrive out of
// order; selecting their bounds does not invent a replacement timestamp.
func mergeObservationTimes(process *model.Process, observedAt ...time.Time) {
	if process.FirstSeen.IsZero() {
		process.FirstSeen = process.LastSeen
	}
	if process.LastSeen.IsZero() {
		process.LastSeen = process.FirstSeen
	}
	if process.LastSeen.Before(process.FirstSeen) {
		process.FirstSeen, process.LastSeen = process.LastSeen, process.FirstSeen
	}
	for _, at := range observedAt {
		if at.IsZero() {
			continue
		}
		if process.FirstSeen.IsZero() || at.Before(process.FirstSeen) {
			process.FirstSeen = at
		}
		if process.LastSeen.IsZero() || at.After(process.LastSeen) {
			process.LastSeen = at
		}
	}
}

// retain is called only while mu is locked. Keeping the eviction queue in a
// linked list makes a full Tetragon execution stream bounded without scanning
// the entire process graph for every event.
func (t *Tracker) retain(process model.Process) {
	t.byKey[process.Key] = process
	entry, exists := t.entries[process.Key]
	if !exists {
		entry = t.recency.PushBack(process.Key)
		t.entries[process.Key] = entry
	}
	if process.ExitedAt != nil {
		t.recency.MoveToFront(entry)
	} else {
		t.recency.MoveToBack(entry)
	}
	for len(t.byKey) > t.maximum {
		oldest := t.recency.Front()
		key := oldest.Value.(string)
		previous := t.byKey[key]
		delete(t.byKey, key)
		delete(t.entries, key)
		if t.current[previous.PID] == key {
			delete(t.current, previous.PID)
		}
		t.recency.Remove(oldest)
	}
}

func (t *Tracker) Get(processKey string) (model.Process, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	process, ok := t.byKey[processKey]
	return process, ok
}

func (t *Tracker) CurrentByPID(pid int) (model.Process, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	key, ok := t.current[pid]
	if !ok {
		return model.Process{}, false
	}
	process, ok := t.byKey[key]
	return process, ok
}

// Ancestors returns nearest parent first. Cycles and corrupted graphs are
// bounded so malformed input cannot cause an infinite traversal.
func (t *Tracker) Ancestors(processKey string, maxDepth int) []model.Process {
	if maxDepth <= 0 {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]model.Process, 0, maxDepth)
	seen := map[string]struct{}{processKey: {}}
	current, ok := t.byKey[processKey]
	for ok && current.ParentKey != "" && len(result) < maxDepth {
		if _, duplicate := seen[current.ParentKey]; duplicate {
			break
		}
		seen[current.ParentKey] = struct{}{}
		parent, exists := t.byKey[current.ParentKey]
		if !exists {
			break
		}
		result = append(result, parent)
		current, ok = parent, true
	}
	return result
}

func (t *Tracker) TreeForPID(pid, maxDepth int) []model.Process {
	process, ok := t.CurrentByPID(pid)
	if !ok {
		return nil
	}
	return append([]model.Process{process}, t.Ancestors(process.Key, maxDepth)...)
}
