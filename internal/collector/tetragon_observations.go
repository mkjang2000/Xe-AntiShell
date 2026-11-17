package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const tetragonFilePolicy = "xeas-file-write-v1"
const tetragonNetworkPolicy = "xeas-network-connect-v1"

type tetragonObservation struct {
	Process      tetragonProcess              `json:"process"`
	Parent       *tetragonProcess             `json:"parent"`
	Ancestors    []tetragonProcess            `json:"ancestors"`
	PolicyName   string                       `json:"policy_name"`
	Function     string                       `json:"function_name"`
	Subsystem    string                       `json:"subsys"`
	Event        string                       `json:"event"`
	Action       string                       `json:"action"`
	ReturnAction string                       `json:"return_action"`
	Args         []map[string]json.RawMessage `json:"args"`
	Data         []json.RawMessage            `json:"data"`
	Return       map[string]json.RawMessage   `json:"return"`
}

type inlinePolicy struct{ runtime, option string }

var tetragonInlinePolicies = map[string]inlinePolicy{
	"xeas-exec-python-c-v1":       {"python", "-c"},
	"xeas-exec-node-e-v1":         {"node", "-e"},
	"xeas-exec-node-eval-v1":      {"node", "--eval"},
	"xeas-exec-node-p-v1":         {"node", "-p"},
	"xeas-exec-node-print-v1":     {"node", "--print"},
	"xeas-exec-php-r-v1":          {"php", "-r"},
	"xeas-exec-perl-e-v1":         {"perl", "-e"},
	"xeas-exec-perl-capital-e-v1": {"perl", "-E"},
	"xeas-exec-ruby-e-v1":         {"ruby", "-e"},
}

var runtimeBinaryPatterns = map[string]*regexp.Regexp{
	"python": regexp.MustCompile(`^python(?:[23](?:\.[0-9]{1,2})?)?$`),
	"node":   regexp.MustCompile(`^node(?:js)?$`),
	"php":    regexp.MustCompile(`^php(?:[578](?:\.[0-9]{1,2})?)?$`),
	"perl":   regexp.MustCompile(`^perl(?:5(?:\.[0-9]{1,2}){1,2})?$`),
	"ruby":   regexp.MustCompile(`^ruby(?:[23](?:\.[0-9]{1,2})?)?$`),
}

func boundedObservationText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func normalizeTetragonObservation(envelope tetragonEnvelope, ingested time.Time, metadata Metadata) (model.Event, error) {
	probe := envelope.ProcessKprobe
	if probe == nil {
		probe = envelope.ProcessTracepoint
	}
	if (envelope.ProcessKprobe != nil && envelope.ProcessTracepoint != nil) || envelope.ProcessExec != nil || envelope.ProcessExit != nil {
		return model.Event{}, errors.New("tetragon observation has conflicting event types")
	}
	_, inline := tetragonInlinePolicies[probe.PolicyName]
	if !inline && probe.PolicyName != tetragonFilePolicy && probe.PolicyName != tetragonNetworkPolicy {
		return model.Event{}, ErrUnsupportedEvent
	}
	source := probe.Process
	if metadata.BootID == "" || envelope.Time.IsZero() || source.PID < 1 || source.StartTime.IsZero() ||
		!boundedObservationText(source.ExecID, 1024) || !boundedObservationText(source.Binary, 4096) || !filepath.IsAbs(source.Binary) {
		return model.Event{}, ErrUnsupportedEvent
	}
	if source.ParentExecID != "" && probe.Parent != nil && probe.Parent.ExecID != "" && source.ParentExecID != probe.Parent.ExecID {
		return model.Event{}, ErrUnsupportedEvent
	}
	if probe.Action != "KPROBE_ACTION_POST" || (probe.ReturnAction != "" && probe.ReturnAction != "KPROBE_ACTION_POST") || len(probe.Data) != 0 {
		return model.Event{}, ErrUnsupportedEvent
	}
	event := model.Event{SchemaVersion: model.SchemaVersion, Source: "tetragon", StreamID: "process", EventTime: envelope.Time.UTC(), IngestTime: ingested.UTC(), Completeness: model.CompletenessComplete,
		RedactedFields: []string{"raw_json", "process.arguments", "parent.arguments", "ancestors.arguments", "process.environment_variables"}}
	metadata.apply(&event)
	switch {
	case inline:
		policy := tetragonInlinePolicies[probe.PolicyName]
		if envelope.ProcessTracepoint == nil || probe.Subsystem != "sched" || probe.Event != "sched_process_exec" || len(probe.Args) != 0 || len(probe.Return) != 0 ||
			!runtimeBinaryPatterns[policy.runtime].MatchString(filepath.Base(source.Binary)) {
			return model.Event{}, ErrUnsupportedEvent
		}
		event.Type = "process.exec_observation"
		event.Execution = &model.ExecutionObservation{Runtime: policy.runtime, Mode: "inline", Evidence: "tetragon_policy", Option: policy.option, PolicyName: probe.PolicyName}
	case probe.PolicyName == tetragonFilePolicy:
		if envelope.ProcessKprobe == nil || probe.Function != "vfs_write" {
			return model.Event{}, ErrUnsupportedEvent
		}
		observation, err := normalizeFileObservation(probe)
		if err != nil {
			return model.Event{}, err
		}
		event.Type, event.File = "file.write", observation
	case probe.PolicyName == tetragonNetworkPolicy:
		if envelope.ProcessKprobe == nil || (probe.Function != "tcp_v4_connect" && probe.Function != "tcp_v6_connect") {
			return model.Event{}, ErrUnsupportedEvent
		}
		observation, err := normalizeNetworkObservation(probe)
		if err != nil {
			return model.Event{}, err
		}
		event.Type, event.Network = "network.connect", observation
	}
	normalizeTetragonContext(&event, source, probe.Parent, probe.Ancestors)
	// These are typed policy facts. Never retain the source's flattened argv,
	// environment, argument buffers or entire event, even with raw storage enabled.
	event.Process.Argv = nil
	for index := range event.Ancestors {
		event.Ancestors[index].Argv = nil
	}
	stable, _ := json.Marshal(struct {
		ExecID, Policy string
		At             time.Time
		Execution      *model.ExecutionObservation
		File           *model.FileObservation
		Network        *model.NetworkObservation
	}{source.ExecID, probe.PolicyName, event.EventTime, event.Execution, event.File, event.Network})
	digest := sha256.Sum256(stable)
	event.SourceEventID = "observation:" + hex.EncodeToString(digest[:])
	event.ID = identity.SourceEventID(event.BootID, event.Source, event.Type, event.SourceEventID)
	return event, nil
}

func singleObservationArgument(probe *tetragonObservation, kind, label string) (json.RawMessage, error) {
	if len(probe.Args) != 1 {
		return nil, ErrUnsupportedEvent
	}
	argument := probe.Args[0]
	var actual string
	if raw, ok := argument["label"]; ok {
		if json.Unmarshal(raw, &actual) != nil || actual != label {
			return nil, ErrUnsupportedEvent
		}
	}
	if len(argument) != 1 && !(len(argument) == 2 && actual == label) {
		return nil, ErrUnsupportedEvent
	}
	raw, ok := argument[kind]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return nil, ErrUnsupportedEvent
	}
	return raw, nil
}

func observationReturn(probe *tetragonObservation, kind string) (*int64, error) {
	if len(probe.Return) == 0 {
		return nil, nil
	}
	for key := range probe.Return {
		if key != kind && key != "label" {
			return nil, ErrUnsupportedEvent
		}
	}
	if raw, exists := probe.Return["label"]; exists {
		var label string
		if json.Unmarshal(raw, &label) != nil || label != "result" {
			return nil, ErrUnsupportedEvent
		}
	}
	raw, ok := probe.Return[kind]
	if !ok || len(raw) > 24 {
		return nil, ErrUnsupportedEvent
	}
	text := string(raw)
	if strings.HasPrefix(text, `"`) {
		if json.Unmarshal(raw, &text) != nil {
			return nil, ErrUnsupportedEvent
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return nil, ErrUnsupportedEvent
	}
	if kind == "int_arg" && (value < -2147483648 || value > 2147483647) {
		return nil, ErrUnsupportedEvent
	}
	return &value, nil
}

func normalizeFileObservation(probe *tetragonObservation) (*model.FileObservation, error) {
	raw, err := singleObservationArgument(probe, "file_arg", "target")
	if err != nil {
		return nil, err
	}
	var file struct {
		Path  string `json:"path"`
		Flags string `json:"flags"`
	}
	if json.Unmarshal(raw, &file) != nil || !boundedObservationText(file.Path, 4096) || !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || file.Flags != "" {
		return nil, ErrUnsupportedEvent
	}
	result, err := observationReturn(probe, "long_arg")
	if err != nil {
		return nil, err
	}
	outcome := "unknown"
	if result != nil {
		switch {
		case *result > 0:
			outcome = "written"
		case *result == 0:
			outcome = "no_data"
		default:
			outcome = "failed"
		}
	}
	return &model.FileObservation{Path: file.Path, Operation: "write", Outcome: outcome, ReturnValue: result, PolicyName: probe.PolicyName, Function: probe.Function}, nil
}

func normalizeNetworkObservation(probe *tetragonObservation) (*model.NetworkObservation, error) {
	raw, err := singleObservationArgument(probe, "sockaddr_arg", "destination")
	if err != nil {
		return nil, err
	}
	var address struct {
		Family string `json:"family"`
		Addr   string `json:"addr"`
		Port   uint32 `json:"port"`
	}
	if json.Unmarshal(raw, &address) != nil || len(address.Addr) > 64 || address.Port < 1 || address.Port > 65535 {
		return nil, ErrUnsupportedEvent
	}
	ip, err := netip.ParseAddr(address.Addr)
	if err != nil || ip.Zone() != "" {
		return nil, ErrUnsupportedEvent
	}
	family := "ipv4"
	if probe.Function == "tcp_v6_connect" {
		family = "ipv6"
	}
	if family == "ipv4" && (address.Family != "AF_INET" || !ip.Is4()) || family == "ipv6" && (address.Family != "AF_INET6" || !ip.Is6()) {
		return nil, ErrUnsupportedEvent
	}
	result, err := observationReturn(probe, "int_arg")
	if err != nil || result != nil && *result > 0 {
		return nil, ErrUnsupportedEvent
	}
	outcome := "unknown"
	if result != nil {
		outcome = "failed"
		if *result == 0 {
			outcome = "initiated"
		}
	}
	return &model.NetworkObservation{Operation: "connect", Protocol: "tcp", Family: family, DestinationAddress: ip.String(), DestinationPort: uint16(address.Port), Outcome: outcome, ReturnValue: result, PolicyName: probe.PolicyName, Function: probe.Function}, nil
}
