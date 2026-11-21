package managed

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func testAgentConfiguration(now time.Time) AgentConfiguration {
	return AgentConfiguration{
		SchemaVersion: SchemaVersion,
		AgentID:       "test-agent",
		EnrollmentID:  "test-enrollment",
		BaseRevision:  1,
		Revision:      3,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
		Set: AgentConfigurationSet{
			Monitoring: &AgentConfigurationMonitoring{SampleIntervalSeconds: 35},
			LocalPanel: &AgentConfigurationLocalPanel{Access: "block"},
		},
		Inherit:                    []string{AgentConfigRetentionKey},
		RetentionReductionApproved: true,
	}
}

func TestAgentConfigurationSignatureIsBoundToTargetRevisionAndTime(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	configuration := testAgentConfiguration(now)
	public, private, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"key-1": public}
	signed, err := SignAgentConfiguration(configuration, "key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip SignedAgentConfiguration
	if err = DecodeStrict(encoded, MaxAgentConfigurationBytes, &roundTrip); err != nil {
		t.Fatal(err)
	}
	accepted, err := VerifyAgentConfiguration(roundTrip, keys, configuration.AgentID, configuration.EnrollmentID, now)
	if err != nil || !reflect.DeepEqual(accepted, configuration) {
		t.Fatalf("configuration round trip: %+v, %v", accepted, err)
	}
	if _, err = VerifyAgentConfiguration(roundTrip, keys, configuration.AgentID, "another-enrollment", now); err == nil {
		t.Fatal("accepted an assignment to a different enrollment")
	}
	if _, err = VerifyAgentConfiguration(roundTrip, keys, configuration.AgentID, configuration.EnrollmentID, configuration.ExpiresAt); err == nil {
		t.Fatal("accepted an assignment at its expiry boundary")
	}
	if _, err = VerifyAgentConfiguration(roundTrip, keys, configuration.AgentID, configuration.EnrollmentID, now.Add(-time.Minute-time.Nanosecond)); err == nil {
		t.Fatal("accepted an assignment issued too far in the future")
	}
	for _, change := range []func(*AgentConfiguration){
		func(c *AgentConfiguration) { c.BaseRevision++ },
		func(c *AgentConfiguration) { c.Revision++ },
		func(c *AgentConfiguration) { c.RetentionReductionApproved = false },
		func(c *AgentConfiguration) { c.Set.LocalPanel = &AgentConfigurationLocalPanel{Access: "allow"} },
	} {
		tampered := roundTrip
		change(&tampered.Configuration)
		if _, err = VerifyAgentConfiguration(tampered, keys, configuration.AgentID, configuration.EnrollmentID, now); err == nil {
			t.Fatal("accepted tampering with signed configuration")
		}
	}
	wrongDomain, err := signValue("policy", roundTrip.KeyID, roundTrip.Configuration, private, MaxAgentConfigurationBytes)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip.Signature = wrongDomain
	if _, err = VerifyAgentConfiguration(roundTrip, keys, configuration.AgentID, configuration.EnrollmentID, now); err == nil {
		t.Fatal("configuration accepted signature from the policy domain")
	}
}

func TestAgentConfigurationRejectsAmbiguousJSON(t *testing.T) {
	for _, input := range []string{
		`null`,
		`{"retention":null}`,
		`{"retention":{"observation_history_minutes":null}}`,
		`{"retention":{},"retention":{"observation_history_minutes":60}}`,
		`{"Monitoring":{"sample_interval_seconds":10}}`,
		`{"monitoring":{"Sample_Interval_Seconds":10}}`,
		`{"monitoring":{"sample_interval_seconds":10,"sample_interval_seconds":15}}`,
		`{"monitoring":{"sample_interval_seconds":10,"heartbeat_interval_seconds":10}}`,
		`{"security_policy":{}}`,
		`{` + strings.Repeat(" ", MaxAgentConfigurationBytes) + `}`,
	} {
		var set AgentConfigurationSet
		if err := json.Unmarshal([]byte(input), &set); err == nil {
			t.Errorf("ambiguous settings accepted: %.100s", input)
		}
	}
	for _, input := range []string{
		`{"configuration":{"inherit":null}}`,
		`{"configuration":{"revision":1,"revision":2}}`,
		`{"configuration":{"retention_reduction_approved":null}}`,
		`{"configuration":{},"key_id":"test","key_id":"test2"}`,
	} {
		var destination SignedAgentConfiguration
		if err := json.Unmarshal([]byte(input), &destination); err == nil {
			t.Errorf("ambiguous assignment accepted: %s", input)
		}
	}
	set := AgentConfigurationSet{LocalPanel: &AgentConfigurationLocalPanel{Access: "block"}}
	if err := json.Unmarshal([]byte(`{}`), &set); err != nil || set.LocalPanel != nil {
		t.Fatalf("reused destination retained an omitted setting: %+v, %v", set, err)
	}
}

func TestAgentConfigurationMergesOnlyRequestedChanges(t *testing.T) {
	prior := AgentConfigurationSet{
		Monitoring: &AgentConfigurationMonitoring{SampleIntervalSeconds: 20},
		Retention:  &AgentConfigurationRetention{ObservationHistoryMinutes: 120},
	}
	inherited := []string{AgentConfigPanelKey}
	patch := AgentConfigurationSet{LocalPanel: &AgentConfigurationLocalPanel{Access: "block"}}
	set, inherit, err := MergeAgentConfiguration(prior, inherited, patch, []string{AgentConfigRetentionKey})
	if err != nil || set.Monitoring.SampleIntervalSeconds != 20 || set.Retention != nil || set.LocalPanel.Access != "block" || !slices.Equal(inherit, []string{AgentConfigRetentionKey}) {
		t.Fatalf("unexpected merged overlay: %+v, %v, %v", set, inherit, err)
	}
	set.Monitoring.SampleIntervalSeconds = 30
	if prior.Monitoring.SampleIntervalSeconds != 20 || !slices.Equal(inherited, []string{AgentConfigPanelKey}) {
		t.Fatal("merged overlay mutates previous state")
	}
	_, ordered, err := MergeAgentConfiguration(AgentConfigurationSet{}, nil, AgentConfigurationSet{}, []string{AgentConfigRetentionKey, AgentConfigSamplingKey, AgentConfigPanelKey})
	if err != nil || !slices.Equal(ordered, []string{AgentConfigPanelKey, AgentConfigSamplingKey, AgentConfigRetentionKey}) {
		t.Fatalf("inherit order: %v, %v", ordered, err)
	}
	if _, _, err = MergeAgentConfiguration(prior, nil, patch, []string{AgentConfigPanelKey}); err == nil {
		t.Fatal("accepted both set and inherit of one key")
	}
}

func TestAgentConfigurationValidatesAllowedFields(t *testing.T) {
	for _, tc := range []struct {
		set     AgentConfigurationSet
		inherit []string
	}{
		{set: AgentConfigurationSet{Monitoring: &AgentConfigurationMonitoring{SampleIntervalSeconds: 4}}},
		{set: AgentConfigurationSet{Monitoring: &AgentConfigurationMonitoring{SampleIntervalSeconds: 3601}}},
		{set: AgentConfigurationSet{Retention: &AgentConfigurationRetention{ObservationHistoryMinutes: 0}}},
		{set: AgentConfigurationSet{Retention: &AgentConfigurationRetention{ObservationHistoryMinutes: 1441}}},
		{set: AgentConfigurationSet{LocalPanel: &AgentConfigurationLocalPanel{Access: "off"}}},
		{inherit: []string{AgentConfigPanelKey, AgentConfigPanelKey}},
		{inherit: []string{"updates.enabled"}},
	} {
		if err := ValidateAgentConfigurationChanges(tc.set, tc.inherit); err == nil {
			t.Errorf("unsupported configuration accepted: %+v", tc)
		}
	}
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	configuration := testAgentConfiguration(now)
	configuration.BaseRevision = configuration.Revision
	if err := configuration.Validate(); err == nil {
		t.Fatal("accepted a revision that does not advance")
	}
	configuration.BaseRevision = 0
	configuration.ExpiresAt = now.Add(24*time.Hour + time.Nanosecond)
	if err := configuration.Validate(); err == nil {
		t.Fatal("accepted excessive validity interval")
	}
}
