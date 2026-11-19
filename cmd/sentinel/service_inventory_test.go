package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

type serviceInventoryFixture map[string]model.Capability

func (f serviceInventoryFixture) Capabilities(context.Context) (model.CapabilityReport, error) {
	return model.CapabilityReport{Capabilities: f}, nil
}

func TestServiceInventoryCommandPreservesAttributionAndSampleState(t *testing.T) {
	snapshot := model.ServiceInventory{
		State:     "partial",
		SampledAt: time.Date(2026, 11, 19, 4, 0, 0, 0, time.UTC),
		Listeners: []model.ServiceListener{
			{Service: "nginx.service", Port: 443, Family: "ipv4", Binding: "wildcard"},
			{Port: 8080, Family: "ipv6", Binding: "loopback"},
		},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]string{"contract": model.ServiceInventoryContract, "state": "partial", "snapshot": string(raw)}
	client := serviceInventoryFixture{model.ServiceInventoryCapability: {Details: details}}
	var output bytes.Buffer
	if err := runServiceInventory(context.Background(), client, nil, &output, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"partial", "nginx.service", "443", "wildcard", "(unknown)", "8080", "ipv6", "loopback"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q in %s", want, output.String())
		}
	}
	details["state"] = "stale"
	output.Reset()
	if err := runServiceInventory(context.Background(), client, nil, &output, true); err != nil {
		t.Fatal(err)
	}
	var reported model.ServiceInventory
	if err := json.Unmarshal(output.Bytes(), &reported); err != nil {
		t.Fatal(err)
	}
	if reported.State != "stale" || !reported.SampledAt.Equal(snapshot.SampledAt) || len(reported.Listeners) != 2 || reported.Listeners[1].Service != "" {
		t.Fatalf("stale JSON inventory = %+v", reported)
	}
}

func TestServiceInventoryCommandDistinguishesMissingAndPendingReports(t *testing.T) {
	var output bytes.Buffer
	if err := runServiceInventory(context.Background(), serviceInventoryFixture{}, nil, &output, true); err == nil || output.Len() != 0 {
		t.Fatalf("missing capability = %q, %v", output.String(), err)
	}
	details := map[string]string{"contract": model.ServiceInventoryContract, "state": "pending"}
	client := serviceInventoryFixture{model.ServiceInventoryCapability: {Details: details}}
	if err := runServiceInventory(context.Background(), client, nil, &output, true); err != nil || !strings.Contains(output.String(), `"state": "pending"`) || !strings.Contains(output.String(), `"listeners": []`) {
		t.Fatalf("pending JSON = %q, %v", output.String(), err)
	}
	details["state"] = "complete"
	output.Reset()
	if err := runServiceInventory(context.Background(), client, nil, &output, true); err == nil || output.Len() != 0 {
		t.Fatalf("complete without a snapshot = %q, %v", output.String(), err)
	}
}
