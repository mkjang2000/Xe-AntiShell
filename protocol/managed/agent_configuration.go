package managed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"
)

const (
	AgentConfigurationCapability = "agent.configuration"
	AgentConfigurationContract   = "1"
	MaxAgentConfigurationBytes   = 16 << 10
	AgentConfigSamplingKey       = "monitoring.sample_interval_seconds"
	AgentConfigRetentionKey      = "retention.observation_history_minutes"
	AgentConfigPanelKey          = "local_panel.access"
	agentConfigurationDomain     = "agent-configuration"
)

// AgentConfiguration is the complete overlay for one enrolled agent. BaseRevision
// names the last accepted overlay and Revision names this assignment.
type AgentConfiguration struct {
	SchemaVersion              string                `json:"schema_version"`
	AgentID                    string                `json:"agent_id"`
	EnrollmentID               string                `json:"enrollment_id"`
	BaseRevision               uint64                `json:"base_revision"`
	Revision                   uint64                `json:"revision"`
	IssuedAt                   time.Time             `json:"issued_at"`
	ExpiresAt                  time.Time             `json:"expires_at"`
	Set                        AgentConfigurationSet `json:"set"`
	Inherit                    []string              `json:"inherit,omitempty"`
	RetentionReductionApproved bool                  `json:"retention_reduction_approved,omitempty"`
}

type AgentConfigurationSet struct {
	Monitoring *AgentConfigurationMonitoring `json:"monitoring,omitempty"`
	Retention  *AgentConfigurationRetention  `json:"retention,omitempty"`
	LocalPanel *AgentConfigurationLocalPanel `json:"local_panel,omitempty"`
}

type AgentConfigurationMonitoring struct {
	SampleIntervalSeconds int `json:"sample_interval_seconds"`
}

type AgentConfigurationRetention struct {
	ObservationHistoryMinutes int `json:"observation_history_minutes"`
}

type AgentConfigurationLocalPanel struct {
	Access string `json:"access"`
}

type SignedAgentConfiguration struct {
	Configuration AgentConfiguration `json:"configuration"`
	KeyID         string             `json:"key_id"`
	Signature     string             `json:"signature"`
}

// AgentConfigurationReport is projected into the heartbeat capability map so
// older centers can continue decoding the unchanged heartbeat envelope.
type AgentConfigurationReport struct {
	RequestedRevision uint64                      `json:"requested_revision"`
	AppliedRevision   uint64                      `json:"applied_revision"`
	Result            string                      `json:"result"`
	Error             string                      `json:"error,omitempty"`
	AppliedAt         *time.Time                  `json:"applied_at,omitempty"`
	Effective         AgentConfigurationEffective `json:"effective"`
}

type AgentConfigurationEffective struct {
	SampleIntervalSeconds          int               `json:"sample_interval_seconds"`
	HeartbeatIntervalSeconds       int               `json:"heartbeat_interval_seconds"`
	ObservationHistoryMinutes      int               `json:"observation_history_minutes"`
	RetentionDays                  int               `json:"retention_days"`
	LocalObservationHistoryMinutes int               `json:"local_observation_history_minutes"`
	LocalRetentionDays             int               `json:"local_retention_days"`
	MaxObservationHistoryMinutes   int               `json:"max_observation_history_minutes"`
	PanelAccess                    string            `json:"panel_access"`
	Sources                        map[string]string `json:"sources"`
}

func (c AgentConfiguration) Validate() error {
	if c.SchemaVersion != SchemaVersion || !validIdentifier(c.AgentID, 128) || !validIdentifier(c.EnrollmentID, 160) || c.Revision <= c.BaseRevision || c.Revision > math.MaxInt64 {
		return errors.New("invalid agent configuration identity or revision")
	}
	if !updateInterval(c.IssuedAt, c.ExpiresAt, 24*time.Hour) {
		return errors.New("invalid agent configuration validity interval")
	}
	return ValidateAgentConfigurationChanges(c.Set, c.Inherit)
}

func ValidateAgentConfigurationChanges(set AgentConfigurationSet, inherit []string) error {
	assigned := map[string]bool{
		AgentConfigSamplingKey:  set.Monitoring != nil,
		AgentConfigRetentionKey: set.Retention != nil,
		AgentConfigPanelKey:     set.LocalPanel != nil,
	}
	for _, key := range inherit {
		setOrSeen, known := assigned[key]
		if !known || setOrSeen {
			return errors.New("invalid, duplicate or conflicting agent configuration inheritance")
		}
		assigned[key] = true
	}
	if v := set.Monitoring; v != nil && (v.SampleIntervalSeconds < 5 || v.SampleIntervalSeconds > 3600) {
		return errors.New("agent resource sample interval must be between 5 and 3600 seconds")
	}
	if v := set.Retention; v != nil && (v.ObservationHistoryMinutes < 60 || v.ObservationHistoryMinutes > 1440) {
		return errors.New("agent observation retention must be between 60 and 1440 minutes")
	}
	if v := set.LocalPanel; v != nil && v.Access != "allow" && v.Access != "block" {
		return errors.New("invalid local panel access decision")
	}
	return nil
}

// MergeAgentConfiguration combines one requested patch with the last applied
// overlay. The new assignment preserves previous decisions for omitted keys.
func MergeAgentConfiguration(priorSet AgentConfigurationSet, priorInherit []string, newSet AgentConfigurationSet, newInherit []string) (AgentConfigurationSet, []string, error) {
	if err := ValidateAgentConfigurationChanges(priorSet, priorInherit); err != nil {
		return AgentConfigurationSet{}, nil, err
	}
	if err := ValidateAgentConfigurationChanges(newSet, newInherit); err != nil {
		return AgentConfigurationSet{}, nil, err
	}
	result := AgentConfigurationSet{
		Monitoring: mergedAgentSetting(priorSet.Monitoring, newSet.Monitoring, newInherit, AgentConfigSamplingKey),
		Retention:  mergedAgentSetting(priorSet.Retention, newSet.Retention, newInherit, AgentConfigRetentionKey),
		LocalPanel: mergedAgentSetting(priorSet.LocalPanel, newSet.LocalPanel, newInherit, AgentConfigPanelKey),
	}
	var inherited []string
	for _, field := range []struct {
		key string
		set bool
	}{
		{AgentConfigPanelKey, result.LocalPanel != nil},
		{AgentConfigSamplingKey, result.Monitoring != nil},
		{AgentConfigRetentionKey, result.Retention != nil},
	} {
		if !field.set && (slices.Contains(priorInherit, field.key) || slices.Contains(newInherit, field.key)) {
			inherited = append(inherited, field.key)
		}
	}
	return result, inherited, nil
}

func mergedAgentSetting[T any](prior, next *T, inherit []string, key string) *T {
	if slices.Contains(inherit, key) {
		return nil
	}
	if next != nil {
		prior = next
	}
	if prior == nil {
		return nil
	}
	value := *prior
	return &value
}

func SignAgentConfiguration(configuration AgentConfiguration, keyID string, private ed25519.PrivateKey) (SignedAgentConfiguration, error) {
	if err := configuration.Validate(); err != nil {
		return SignedAgentConfiguration{}, err
	}
	signature, err := signValue(agentConfigurationDomain, keyID, configuration, private, MaxAgentConfigurationBytes)
	if err != nil {
		return SignedAgentConfiguration{}, err
	}
	return SignedAgentConfiguration{Configuration: configuration, KeyID: keyID, Signature: signature}, nil
}

// VerifyAgentConfiguration verifies a new assignment. Applying it still requires
// an exact BaseRevision match with the agent's last durable successful revision.
func VerifyAgentConfiguration(signed SignedAgentConfiguration, trusted map[string]ed25519.PublicKey, agentID, enrollmentID string, now time.Time) (AgentConfiguration, error) {
	c := signed.Configuration
	if err := c.Validate(); err != nil {
		return AgentConfiguration{}, err
	}
	if err := verifyValue(agentConfigurationDomain, signed.KeyID, c, signed.Signature, trusted, MaxAgentConfigurationBytes); err != nil {
		return AgentConfiguration{}, err
	}
	if c.AgentID != agentID || c.EnrollmentID != enrollmentID || !updateCurrent(c.IssuedAt, c.ExpiresAt, now) {
		return AgentConfiguration{}, errors.New("agent configuration target or time rejected")
	}
	return c, nil
}

func (c *SignedAgentConfiguration) UnmarshalJSON(data []byte) error {
	type fields SignedAgentConfiguration
	return decodeAgentConfigurationObject(data, (*fields)(c), "configuration", "key_id", "signature")
}

func (c *AgentConfiguration) UnmarshalJSON(data []byte) error {
	type fields AgentConfiguration
	return decodeAgentConfigurationObject(data, (*fields)(c), "schema_version", "agent_id", "enrollment_id", "base_revision", "revision", "issued_at", "expires_at", "set", "inherit", "retention_reduction_approved")
}

func (set *AgentConfigurationSet) UnmarshalJSON(data []byte) error {
	type fields AgentConfigurationSet
	return decodeAgentConfigurationObject(data, (*fields)(set), "monitoring", "retention", "local_panel")
}

func (value *AgentConfigurationMonitoring) UnmarshalJSON(data []byte) error {
	type fields AgentConfigurationMonitoring
	return decodeAgentConfigurationObject(data, (*fields)(value), "sample_interval_seconds")
}

func (value *AgentConfigurationRetention) UnmarshalJSON(data []byte) error {
	type fields AgentConfigurationRetention
	return decodeAgentConfigurationObject(data, (*fields)(value), "observation_history_minutes")
}

func (value *AgentConfigurationLocalPanel) UnmarshalJSON(data []byte) error {
	type fields AgentConfigurationLocalPanel
	return decodeAgentConfigurationObject(data, (*fields)(value), "access")
}

// decodeAgentConfigurationObject preserves the meaning of omission and refuses
// alternate field spellings or duplicate keys before decoding typed fields.
func decodeAgentConfigurationObject[T any](data []byte, destination *T, keys ...string) error {
	if len(data) > MaxAgentConfigurationBytes {
		return errors.New("agent configuration exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if opening, err := decoder.Token(); err != nil || opening != json.Delim('{') {
		return errors.New("agent configuration must be a JSON object")
	}
	seen := make(map[string]bool, len(keys))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || !slices.Contains(keys, key) {
			return errors.New("invalid or duplicate agent configuration field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("agent configuration field %q cannot be null", key)
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return errors.New("incomplete agent configuration object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("agent configuration contains trailing data")
	}
	var decoded T
	if err := DecodeStrict(data, MaxAgentConfigurationBytes, &decoded); err != nil {
		return err
	}
	*destination = decoded
	return nil
}
