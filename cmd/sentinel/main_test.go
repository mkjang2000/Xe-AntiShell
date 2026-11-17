package main

import (
	"bytes"
	"strings"
	"testing"
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
