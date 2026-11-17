package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCapabilityStateValid(t *testing.T) {
	for _, state := range []CapabilityState{CapabilitySupported, CapabilityLimited, CapabilityUnsupported, CapabilityError} {
		if !state.Valid() {
			t.Fatalf("expected %q to be valid", state)
		}
	}
	if CapabilityState("unknown-state").Valid() {
		t.Fatal("unexpected valid state")
	}
}

func TestEventJSONUsesStableFieldNames(t *testing.T) {
	now := time.Date(2026, 11, 16, 1, 2, 3, 0, time.UTC)
	event := Event{
		SchemaVersion: SchemaVersion,
		ID:            "event-1",
		BootID:        "boot-1",
		EventTime:     now,
		IngestTime:    now,
		Type:          "process.exec",
		Source:        "test",
		Completeness:  CompletenessComplete,
		Process: Process{
			Key:               "process-1",
			PID:               42,
			UID:               -1,
			EUID:              0,
			GID:               -1,
			EGID:              -1,
			LineageConfidence: LineageUnknown,
		},
		RawJSON: json.RawMessage(`{"source":true}`),
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "event_id", "event_type", "process", "raw_json"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}

func TestCapabilityReportLookup(t *testing.T) {
	report := CapabilityReport{Capabilities: map[string]Capability{
		"kernel.btf": {Name: "kernel.btf", State: CapabilitySupported},
	}}
	got, ok := report.Capability("kernel.btf")
	if !ok || got.State != CapabilitySupported {
		t.Fatalf("unexpected lookup result: %#v, %v", got, ok)
	}
}
