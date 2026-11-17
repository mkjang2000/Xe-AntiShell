// Package config loads and validates the standalone agent configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const CurrentVersion = 1

type CollectorMode string

const (
	CollectorAuto     CollectorMode = "auto"
	CollectorTetragon CollectorMode = "tetragon"
	CollectorAudit    CollectorMode = "audit"
	CollectorReplay   CollectorMode = "replay"
	CollectorDisabled CollectorMode = "disabled"
)

type Config struct {
	Version   int             `json:"version" yaml:"version"`
	Agent     AgentConfig     `json:"agent" yaml:"agent"`
	Collector CollectorConfig `json:"collector" yaml:"collector"`
	Limits    LimitsConfig    `json:"limits" yaml:"limits"`
	Privacy   PrivacyConfig   `json:"privacy" yaml:"privacy"`
	Detection DetectionConfig `json:"detection" yaml:"detection"`
	Response  ResponseConfig  `json:"response" yaml:"response"`
}

// AllowTerminate is an explicit host opt-in in addition to a signed policy.
// It defaults to false for existing installations and cannot be enabled by
// central policy alone.
type ResponseConfig struct {
	AllowTerminate bool `json:"allow_terminate" yaml:"allow_terminate"`
}

type AgentConfig struct {
	ID           string `json:"id,omitempty" yaml:"id,omitempty"`
	SocketPath   string `json:"socket_path" yaml:"socket_path"`
	DatabasePath string `json:"database_path" yaml:"database_path"`
}

type CollectorConfig struct {
	Mode     CollectorMode  `json:"mode" yaml:"mode"`
	Tetragon TetragonConfig `json:"tetragon" yaml:"tetragon"`
	Audit    AuditConfig    `json:"audit" yaml:"audit"`
	Replay   ReplayConfig   `json:"replay" yaml:"replay"`
}

type TetragonConfig struct {
	Command              string   `json:"command" yaml:"command"`
	Args                 []string `json:"args" yaml:"args"`
	IncludeExecutables   []string `json:"include_executables,omitempty" yaml:"include_executables,omitempty"`
	OnlyDetectionOrigins bool     `json:"only_detection_origins" yaml:"only_detection_origins"`
}

type AuditConfig struct {
	InputPath            string   `json:"input_path,omitempty" yaml:"input_path,omitempty"`
	IncludeExecutables   []string `json:"include_executables,omitempty" yaml:"include_executables,omitempty"`
	OnlyDetectionOrigins bool     `json:"only_detection_origins" yaml:"only_detection_origins"`
}

type ReplayConfig struct {
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
}

type LimitsConfig struct {
	MaxEventBytes int `json:"max_event_bytes" yaml:"max_event_bytes"`
	MaxRawJSON    int `json:"max_raw_json_bytes" yaml:"max_raw_json_bytes"`
	MaxArgv       int `json:"max_argv" yaml:"max_argv"`
	MaxArgument   int `json:"max_argument_bytes" yaml:"max_argument_bytes"`
	QueueSize     int `json:"queue_size" yaml:"queue_size"`
	QueryDefault  int `json:"query_default" yaml:"query_default"`
	QueryMaximum  int `json:"query_maximum" yaml:"query_maximum"`
	RetentionDays int `json:"retention_days" yaml:"retention_days"`
}

type PrivacyConfig struct {
	StoreRawEvents         bool     `json:"store_raw_events" yaml:"store_raw_events"`
	RedactArgv             bool     `json:"redact_argv" yaml:"redact_argv"`
	SensitiveArgumentNames []string `json:"sensitive_argument_names" yaml:"sensitive_argument_names"`
}

type DetectionConfig struct {
	Enabled              bool     `json:"enabled" yaml:"enabled"`
	ExtendedProcessRules bool     `json:"extended_process_rules,omitempty" yaml:"extended_process_rules,omitempty"`
	WebExecutables       []string `json:"web_executables" yaml:"web_executables"`
	WebServices          []string `json:"web_services,omitempty" yaml:"web_services,omitempty"`
	Shells               []string `json:"shells" yaml:"shells"`
	AllowedPairs         []string `json:"allowed_pairs,omitempty" yaml:"allowed_pairs,omitempty"`
}

func Default() Config {
	return Config{
		Version: CurrentVersion,
		Agent: AgentConfig{
			SocketPath:   "/run/xe-antishell/sentineld.sock",
			DatabasePath: "/var/lib/xe-antishell/sentinel.db",
		},
		Collector: CollectorConfig{
			Mode: CollectorAuto,
			Tetragon: TetragonConfig{
				Command: "/usr/bin/tetra",
				Args:    []string{"getevents", "-o", "json"},
			},
		},
		Limits: LimitsConfig{
			MaxEventBytes: 256 << 10,
			MaxRawJSON:    128 << 10,
			MaxArgv:       128,
			MaxArgument:   4096,
			QueueSize:     256,
			QueryDefault:  100,
			QueryMaximum:  1000,
			RetentionDays: 7,
		},
		Privacy: PrivacyConfig{
			StoreRawEvents: false,
			RedactArgv:     true,
			SensitiveArgumentNames: []string{
				"password", "passwd", "token", "access-token", "api-key",
				"apikey", "secret", "client-secret", "authorization",
			},
		},
		Detection: DetectionConfig{
			Enabled:        true,
			WebExecutables: []string{"nginx", "httpd", "apache2", "php-fpm"},
			Shells:         []string{"sh", "bash", "dash", "zsh", "ksh"},
		},
	}
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	cfg, err := Decode(f)
	if err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	return cfg, nil
}

// Decode applies safe defaults before decoding and rejects unknown fields and
// additional YAML documents. An empty file is equivalent to the defaults.
func Decode(r io.Reader) (Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, err
	}

	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("multiple YAML documents are not allowed")
		}
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if err := validateAbsolutePath("agent.socket_path", c.Agent.SocketPath); err != nil {
		return err
	}
	if err := validateAbsolutePath("agent.database_path", c.Agent.DatabasePath); err != nil {
		return err
	}
	if filepath.Clean(c.Agent.SocketPath) == filepath.Clean(c.Agent.DatabasePath) {
		return errors.New("agent.socket_path and agent.database_path must differ")
	}
	if strings.ContainsRune(c.Agent.ID, '\x00') {
		return errors.New("agent.id contains NUL")
	}

	switch c.Collector.Mode {
	case CollectorAuto, CollectorTetragon, CollectorAudit, CollectorReplay, CollectorDisabled:
	default:
		return fmt.Errorf("invalid collector.mode %q", c.Collector.Mode)
	}
	if c.Collector.Mode == CollectorTetragon || c.Collector.Mode == CollectorAuto {
		if strings.TrimSpace(c.Collector.Tetragon.Command) == "" {
			return errors.New("collector.tetragon.command must not be empty")
		}
		if hasNUL(c.Collector.Tetragon.Command) || anyHasNUL(c.Collector.Tetragon.Args) {
			return errors.New("collector.tetragon command or args contain NUL")
		}
		if !filepath.IsAbs(c.Collector.Tetragon.Command) {
			return errors.New("collector.tetragon.command must be an absolute path")
		}
	}
	if c.Collector.Audit.InputPath != "" {
		if err := validateAbsolutePath("collector.audit.input_path", c.Collector.Audit.InputPath); err != nil {
			return err
		}
	}
	if err := validateExecutableBasenames("collector.audit.include_executables", c.Collector.Audit.IncludeExecutables); err != nil {
		return err
	}
	if err := validateExecutableBasenames("collector.tetragon.include_executables", c.Collector.Tetragon.IncludeExecutables); err != nil {
		return err
	}
	// Check both sources so auto mode and later collector switches cannot silently
	// narrow the executable coverage required by the extended process rules.
	if c.Detection.ExtendedProcessRules {
		if len(c.Collector.Audit.IncludeExecutables) != 0 {
			return errors.New("detection.extended_process_rules requires empty collector.audit.include_executables")
		}
		if len(c.Collector.Tetragon.IncludeExecutables) != 0 {
			return errors.New("detection.extended_process_rules requires empty collector.tetragon.include_executables")
		}
	}
	if c.Collector.Tetragon.OnlyDetectionOrigins && !c.Detection.Enabled {
		return errors.New("collector.tetragon.only_detection_origins requires detection.enabled")
	}
	if c.Collector.Audit.OnlyDetectionOrigins && !c.Detection.Enabled {
		return errors.New("collector.audit.only_detection_origins requires detection.enabled")
	}
	if c.Collector.Mode == CollectorReplay {
		if err := validateAbsolutePath("collector.replay.path", c.Collector.Replay.Path); err != nil {
			return err
		}
	}

	if c.Limits.MaxEventBytes < 1024 {
		return errors.New("limits.max_event_bytes must be at least 1024")
	}
	if c.Limits.MaxRawJSON < 0 || c.Limits.MaxRawJSON > c.Limits.MaxEventBytes {
		return errors.New("limits.max_raw_json_bytes must be between 0 and max_event_bytes")
	}
	if c.Limits.MaxArgv < 1 || c.Limits.MaxArgv > 65536 {
		return errors.New("limits.max_argv must be between 1 and 65536")
	}
	if c.Limits.MaxArgument < 1 || c.Limits.MaxArgument > c.Limits.MaxEventBytes {
		return errors.New("limits.max_argument_bytes must be positive and no greater than max_event_bytes")
	}
	if c.Limits.QueueSize < 1 || c.Limits.QueueSize > 1_000_000 {
		return errors.New("limits.queue_size must be between 1 and 1000000")
	}
	if int64(c.Limits.QueueSize)*int64(c.Limits.MaxEventBytes) > 512<<20 {
		return errors.New("limits.queue_size multiplied by max_event_bytes must not exceed 512 MiB")
	}
	if c.Limits.QueryDefault < 1 || c.Limits.QueryMaximum < c.Limits.QueryDefault || c.Limits.QueryMaximum > 100_000 {
		return errors.New("query limits require 1 <= query_default <= query_maximum <= 100000")
	}
	if c.Limits.RetentionDays < 1 || c.Limits.RetentionDays > 3650 {
		return errors.New("limits.retention_days must be between 1 and 3650")
	}
	if c.Privacy.RedactArgv {
		if err := validateUniqueList("privacy.sensitive_argument_names", c.Privacy.SensitiveArgumentNames); err != nil {
			return err
		}
	} else if err := validateUniqueListAllowEmpty("privacy.sensitive_argument_names", c.Privacy.SensitiveArgumentNames); err != nil {
		return err
	}

	if c.Detection.Enabled {
		if err := validateUniqueListAllowEmpty("detection.web_executables", c.Detection.WebExecutables); err != nil {
			return err
		}
		if err := validateUniqueListAllowEmpty("detection.web_services", c.Detection.WebServices); err != nil {
			return err
		}
		if len(c.Detection.WebExecutables) == 0 && len(c.Detection.WebServices) == 0 {
			return errors.New("detection requires at least one web executable or web service when enabled")
		}
		if err := validateUniqueList("detection.shells", c.Detection.Shells); err != nil {
			return err
		}
	} else if err := validateUniqueListAllowEmpty("detection.web_services", c.Detection.WebServices); err != nil {
		return err
	}
	if err := validateUniqueListAllowEmpty("detection.allowed_pairs", c.Detection.AllowedPairs); err != nil {
		return err
	}
	for _, pair := range c.Detection.AllowedPairs {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("detection.allowed_pairs value %q must use web-origin:shell", pair)
		}
	}
	return nil
}

func validateAbsolutePath(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if hasNUL(value) {
		return fmt.Errorf("%s contains NUL", name)
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be absolute", name)
	}
	if filepath.Clean(value) == string(filepath.Separator) {
		return fmt.Errorf("%s must not be the filesystem root", name)
	}
	return nil
}

func validateUniqueList(name string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty when detection is enabled", name)
	}
	return validateUniqueListAllowEmpty(name, values)
}

func validateUniqueListAllowEmpty(name string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || hasNUL(value) {
			return fmt.Errorf("%s contains an empty or invalid value", name)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s contains duplicate value %q", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateExecutableBasenames(name string, values []string) error {
	if err := validateUniqueListAllowEmpty(name, values); err != nil {
		return err
	}
	for _, value := range values {
		if value != strings.TrimSpace(value) || value == "." || filepath.Base(value) != value {
			return fmt.Errorf("%s value %q must be an executable basename", name, value)
		}
	}
	return nil
}

func anyHasNUL(values []string) bool {
	for _, value := range values {
		if hasNUL(value) {
			return true
		}
	}
	return false
}

func hasNUL(value string) bool {
	return strings.ContainsRune(value, '\x00')
}
