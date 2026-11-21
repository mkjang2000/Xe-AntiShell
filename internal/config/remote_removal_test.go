package config

import (
	"strings"
	"testing"
)

func TestRemoteRemovalDefaultsToEnabledAndHonorsHostOptOut(t *testing.T) {
	cfg, err := Decode(strings.NewReader("version: 1\n"))
	if err != nil || !cfg.Central.RemoteRemovalEnabled {
		t.Fatalf("missing host setting did not default to enabled: %v", err)
	}
	cfg, err = Decode(strings.NewReader("version: 1\ncentral:\n  remote_removal_enabled: false\n"))
	if err != nil || cfg.Central.RemoteRemovalEnabled {
		t.Fatalf("host opt-out was ignored: %v", err)
	}
	if _, err := Decode(strings.NewReader("version: 1\ncentral:\n  remote_removal_command: /custom\n")); err == nil {
		t.Fatal("unexpected configuration field was accepted")
	}
}
