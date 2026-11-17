package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeDefaultsAndOverrides(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`
version: 1
agent:
  id: web-01
collector:
  mode: audit
  audit:
    include_executables: [sh, bash]
    only_detection_origins: true
limits:
  retention_days: 30
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.ID != "web-01" || cfg.Collector.Mode != CollectorAudit {
		t.Fatalf("overrides not applied: %#v", cfg)
	}
	if cfg.Agent.SocketPath == "" || cfg.Limits.QueueSize == 0 {
		t.Fatalf("defaults were not retained: %#v", cfg)
	}
	if cfg.Limits.RetentionDays != 30 {
		t.Fatalf("unexpected retention: %d", cfg.Limits.RetentionDays)
	}
	if len(cfg.Collector.Audit.IncludeExecutables) != 2 || cfg.Collector.Audit.IncludeExecutables[1] != "bash" {
		t.Fatalf("audit executable filter not decoded: %#v", cfg.Collector.Audit.IncludeExecutables)
	}
	if !cfg.Collector.Audit.OnlyDetectionOrigins {
		t.Fatal("audit detection-origin filter was not decoded")
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	_, err := Decode(strings.NewReader("version: 1\nunknown: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestDecodeRejectsAdditionalDocument(t *testing.T) {
	_, err := Decode(strings.NewReader("version: 1\n---\nversion: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple document error, got %v", err)
	}
}

func TestDecodeRejectsUnsafeOrInconsistentValues(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"relative socket", "agent:\n  socket_path: relative.sock\n"},
		{"replay without path", "collector:\n  mode: replay\n"},
		{"relative tetragon command", "collector:\n  tetragon:\n    command: tetra\n"},
		{"raw larger than event", "limits:\n  max_event_bytes: 1024\n  max_raw_json_bytes: 2048\n"},
		{"unsafe queue memory", "limits:\n  max_event_bytes: 1048576\n  queue_size: 1024\n"},
		{"duplicate executable", "detection:\n  web_executables: [nginx, nginx]\n"},
		{"duplicate audit executable", "collector:\n  audit:\n    include_executables: [bash, bash]\n"},
		{"audit executable path", "collector:\n  audit:\n    include_executables: [/bin/bash]\n"},
		{"tetragon executable path", "collector:\n  tetragon:\n    include_executables: [/bin/bash]\n"},
		{"tetragon origin filter without detection", "collector:\n  tetragon:\n    only_detection_origins: true\ndetection:\n  enabled: false\n"},
		{"audit executable whitespace", "collector:\n  audit:\n    include_executables: [' bash ']\n"},
		{"origin filter without detection", "collector:\n  audit:\n    only_detection_origins: true\ndetection:\n  enabled: false\n"},
		{"duplicate service", "detection:\n  web_services: [api.service, api.service]\n"},
		{"no web origins", "detection:\n  web_executables: []\n  web_services: []\n"},
		{"malformed allowed pair", "detection:\n  allowed_pairs: [nginx-bash]\n"},
		{"empty sensitive argument", "privacy:\n  sensitive_argument_names: [password, '']\n"},
		{"unknown mode", "collector:\n  mode: magic\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(test.yaml)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDetectionAcceptsServiceOnlyOrigins(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`
detection:
  web_executables: []
  web_services:
    - orders-api.service
  shells: [sh]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Detection.WebServices) != 1 || cfg.Detection.WebServices[0] != "orders-api.service" {
		t.Fatalf("web services not decoded: %#v", cfg.Detection.WebServices)
	}
}

func TestDetectionCanBeExplicitlyDisabled(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`
detection:
  enabled: false
  web_executables: []
  shells: []
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Detection.Enabled {
		t.Fatal("detection should be disabled")
	}
}

func TestEmptyFileUsesDefaults(t *testing.T) {
	cfg, err := Decode(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != CurrentVersion || cfg.Collector.Mode != CollectorAuto {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if cfg.Detection.ExtendedProcessRules {
		t.Fatal("extended process rules must remain opt-in")
	}
}

func TestExtendedProcessRulesRequireUnfilteredExecutables(t *testing.T) {
	for _, mode := range []CollectorMode{CollectorAuto, CollectorTetragon, CollectorAudit, CollectorReplay, CollectorDisabled} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := Default()
			cfg.Collector.Mode = mode
			cfg.Collector.Replay.Path = "/tmp/events.ndjson"
			cfg.Detection.ExtendedProcessRules = true
			if err := cfg.Validate(); err != nil {
				t.Fatalf("unfiltered extended rules rejected: %v", err)
			}
			for _, source := range []string{"audit", "tetragon"} {
				t.Run(source, func(t *testing.T) {
					filtered := cfg
					if source == "audit" {
						filtered.Collector.Audit.IncludeExecutables = []string{"sh"}
					} else {
						filtered.Collector.Tetragon.IncludeExecutables = []string{"sh"}
					}
					if err := filtered.Validate(); err == nil || !strings.Contains(err.Error(), "collector."+source+".include_executables") {
						t.Fatalf("expected executable coverage error, got %v", err)
					}
					filtered.Detection.ExtendedProcessRules = false
					if err := filtered.Validate(); err != nil {
						t.Fatalf("legacy filtered configuration rejected: %v", err)
					}
				})
			}
		})
	}
}

func TestExampleConfigurations(t *testing.T) {
	for _, test := range []struct {
		path         string
		wantExtended bool
	}{
		{"../../configs/sentineld.yaml", false},
		{"../../configs/examples/agent-tetragon.yaml", false},
		{"../../configs/examples/agent-webshell-detection.yaml", true},
	} {
		t.Run(filepath.Base(test.path), func(t *testing.T) {
			cfg, err := Load(test.path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Detection.ExtendedProcessRules != test.wantExtended {
				t.Fatalf("extended process rules = %t, want %t", cfg.Detection.ExtendedProcessRules, test.wantExtended)
			}
			if cfg.Response.AllowTerminate {
				t.Fatal("shared configuration must not opt in to automatic termination")
			}
		})
	}
}
