package config

import "testing"

func TestLocalPrivilegeOptInRejectsNarrowedSourceArguments(t *testing.T) {
	for _, mode := range []CollectorMode{CollectorTetragon, CollectorAuto} {
		cfg := Default()
		cfg.Collector.Mode = mode
		cfg.Collector.Tetragon.Args = []string{"getevents", "-o", "json", "--event-types=PROCESS_EXEC"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("legacy opt-out config was changed: %v", err)
		}
		cfg.Detection.PrivilegeRules = true
		if err := cfg.Validate(); err == nil {
			t.Fatalf("local opt-in accepted source filter in %s", mode)
		}
		cfg.Collector.Tetragon.Args = []string{"--server-address", "unix:///run/tetragon/tetragon.sock", "getevents", "-o", "json", "--exclude-fields", "process.arguments,process.environment_variables,parent.arguments,parent.environment_variables,ancestors.arguments,ancestors.environment_variables"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("installed privacy-only source rejected in %s: %v", mode, err)
		}
	}
}
