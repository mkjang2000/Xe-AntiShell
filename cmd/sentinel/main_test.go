package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestVersionDoesNotRequireDaemon(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) != version {
		t.Fatalf("unexpected version output %q", stdout.String())
	}
}

func TestHumanStatusCollectionGap(t *testing.T) {
	start := time.Date(2026, 1, 10, 10, 0, 0, 123456789, time.UTC)
	end := start.Add(40 * time.Second)
	details := map[string]string{"last_disconnect_at": start.Format(time.RFC3339Nano), "reconnect_attempts": "3"}
	status := model.AgentStatus{Collector: "tetragon-json", CapabilityReport: &model.CapabilityReport{
		Capabilities: map[string]model.Capability{"collector.tetragon": {Details: details}},
	}}
	verify := func(want string) {
		t.Helper()
		var output bytes.Buffer
		writeCollectorGap(&output, status)
		if output.String() != want {
			t.Fatalf("collection gap output = %q, want %q", output.String(), want)
		}
	}
	prefix := "Last collection interruption: " + start.Local().Format(time.RFC3339Nano) + "\nCollection recovery: "
	const attempts = "\nReconnect attempts since startup: 3\n"
	verify(prefix + "pending" + attempts)
	details["last_recovered_at"] = end.Format(time.RFC3339Nano)
	verify(prefix + end.Local().Format(time.RFC3339Nano) + attempts)
	status.Collector = "audit-dispatcher"
	verify("")
	status.Collector = "tetragon-json"
	delete(details, "last_disconnect_at")
	verify("")
	status.CapabilityReport = nil
	verify("")
}

func TestDefaultSocketMatchesDaemonConfiguration(t *testing.T) {
	if defaultSocketPath != "/run/xe-antishell/sentineld.sock" {
		t.Fatalf("unexpected default socket %q", defaultSocketPath)
	}
}

func TestCommandRejectsIgnoredArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	tests := [][]string{
		{"version", "extra"},
		{"status", "extra"},
		{"capabilities", "extra"},
		{"service-inventory", "extra"},
		{"events", "extra"},
		{"findings", "extra"},
		{"process-tree", "--pid", "1", "extra"},
		{"audit-plugin", "extra"},
	}
	for _, args := range tests {
		if err := run(args, &stdout, &stderr); err == nil {
			t.Errorf("run(%v) unexpectedly accepted extra arguments", args)
		}
		stdout.Reset()
		stderr.Reset()
	}
}

func TestCLIValidatesSecuritySensitiveFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	tests := [][]string{
		{"--socket", "relative.sock", "version"},
		{"process-tree", "--pid", "0"},
		{"events", "--limit", "0"},
		{"audit-plugin", "--max-line-bytes", "0"},
		{"audit-plugin", "--max-line-bytes", "67108865"},
	}
	for _, args := range tests {
		if err := run(args, &stdout, &stderr); err == nil {
			t.Errorf("run(%v) unexpectedly succeeded", args)
		}
		stdout.Reset()
		stderr.Reset()
	}
}
