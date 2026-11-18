package main

import (
	"bytes"
	"strings"
	"testing"

	"xe-antishell/internal/model"
)

func TestCapacityPreservesMissingAndZeroMeasurements(t *testing.T) {
	var out bytes.Buffer
	status := model.AgentStatus{}
	if err := writeCapacity(&out, status, false); err == nil {
		t.Fatal("accepted a missing capability report")
	}
	details := map[string]string{"stored_events_today": "0", "queue_high_water": "2", "drop_invalid": "0"}
	status.CapabilityReport = &model.CapabilityReport{Capabilities: map[string]model.Capability{
		"storage.capacity": {Name: "storage.capacity", Details: details},
	}}
	if err := writeCapacity(&out, status, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Central delivery measurements unavailable") {
		t.Fatalf("expected absent central metrics: %s", out.String())
	}
	for _, want := range []string{"stored_events_today 0", "stored_events_yesterday unmeasured", "drop_invalid 0", "queue_high_water 2"} {
		if !strings.Contains(strings.Join(strings.Fields(out.String()), " "), want) {
			t.Errorf("missing %q: %s", want, out.String())
		}
	}
	details["pending_records"] = "0"
	details["lost_records"] = "0"
	details["first_recovery_ack_at"] = "2026-01-01T00:00:01Z"
	details["ack_recovery_seconds"] = "0.2"
	out.Reset()
	if err := writeCapacity(&out, status, false); err != nil {
		t.Fatal(err)
	}
	rendered := strings.Join(strings.Fields(out.String()), " ")
	for _, want := range []string{"pending_records 0", "ack_recovery_seconds 0.2", "drained_at unmeasured"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q: %s", want, rendered)
		}
	}
	out.Reset()
	if err := writeCapacity(&out, status, true); err != nil || !strings.Contains(out.String(), `"lost_records": "0"`) || strings.Contains(out.String(), "drained_at") {
		t.Fatalf("machine-readable capacity = %s, err = %v", out.String(), err)
	}
}
