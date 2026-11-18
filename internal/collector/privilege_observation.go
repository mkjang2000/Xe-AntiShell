package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const tetragonCredentialPolicy = "xeas-credential-change-v1"

// Only the reviewed monitor-only policy tuple can supply credential evidence.
// Before is copied from current_task.cred in the same entry event as argument0
// (After); the paired return is merged by Tetragon's TID/entry-ktime key.
func normalizeTetragonCredential(envelope tetragonEnvelope, ingested time.Time, metadata Metadata) (model.Event, error) {
	probe := envelope.ProcessKprobe
	if probe == nil || envelope.ProcessTracepoint != nil || envelope.ProcessExec != nil || envelope.ProcessExit != nil ||
		probe.PolicyName != tetragonCredentialPolicy || probe.Function != "commit_creds" || probe.Subsystem != "" || probe.Event != "" ||
		probe.Action != "KPROBE_ACTION_POST" || probe.ReturnAction != "" && probe.ReturnAction != "KPROBE_ACTION_POST" || len(probe.Args) != 1 || len(probe.Data) != 4 {
		return model.Event{}, ErrUnsupportedEvent
	}
	source := probe.Process
	if metadata.BootID == "" || envelope.Time.IsZero() || source.PID < 1 || source.StartTime.IsZero() ||
		!boundedObservationText(source.ExecID, 1024) || !boundedObservationText(source.Binary, 4096) || !filepath.IsAbs(source.Binary) ||
		source.ParentExecID != "" && probe.Parent != nil && probe.Parent.ExecID != "" && source.ParentExecID != probe.Parent.ExecID {
		return model.Event{}, ErrUnsupportedEvent
	}
	afterRaw, err := credentialArgument(probe.Args[0], "process_credentials_arg", "after")
	if err != nil {
		return model.Event{}, err
	}
	var data [4]map[string]json.RawMessage
	for index := range data {
		if err := decodeSingleJSON(probe.Data[index], &data[index]); err != nil {
			return model.Event{}, ErrUnsupportedEvent
		}
	}
	beforeRaw, err := credentialArgument(data[0], "process_credentials_arg", "before")
	if err != nil {
		return model.Event{}, err
	}
	tid, err := credentialPositiveInteger(data[1], "int_arg", "tid", 31)
	if err != nil {
		return model.Event{}, err
	}
	taskStart, err := credentialPositiveInteger(data[2], "size_arg", "task_start", 64)
	if err != nil {
		return model.Event{}, err
	}
	tgid, err := credentialPositiveInteger(data[3], "int_arg", "tgid", 31)
	if err != nil || uint64(source.PID) != tgid || source.TID != 0 && uint64(source.TID) != tid {
		// Tetragon may fall back to a fork ancestor's cached exec. Do not
		// attach another task's credential changes to that ancestor's PID.
		return model.Event{}, ErrUnsupportedEvent
	}
	before, err := decodeTetragonCredentials(beforeRaw)
	if err != nil {
		return model.Event{}, err
	}
	after, err := decodeTetragonCredentials(afterRaw)
	if err != nil {
		return model.Event{}, err
	}
	result, err := observationReturn(probe, "int_arg")
	if err != nil || result != nil && *result > 0 {
		return model.Event{}, ErrUnsupportedEvent
	}
	observation := &model.CredentialObservation{Before: before.snapshot, After: after.snapshot, TGID: int(tgid), TID: int(tid), TaskStartTimeNS: taskStart,
		Evidence: model.CredentialEvidence, PolicyName: probe.PolicyName, Function: probe.Function, ReturnValue: result, Outcome: "unknown"}
	if result != nil {
		if *result < 0 {
			observation.Outcome = "failed"
		} else if before.complete && after.complete {
			observation.Outcome = "applied"
		}
	}
	// Identity/tuple/result were checked above and each fresh snapshot was
	// validated exactly once while decoding. Keep those local facts here;
	// public consumers still validate independently after ownership transfer.
	if before.complete && after.complete && reflect.DeepEqual(before.snapshot, after.snapshot) {
		// commit_creds also runs on unchanged exec credentials. This is an
		// intentional userspace filter, not a dropped kernel event.
		return model.Event{}, ErrUnsupportedEvent
	}
	event := model.Event{SchemaVersion: model.SchemaVersion, Source: "tetragon", StreamID: "process", Type: "process.credential_change",
		EventTime: envelope.Time.UTC(), IngestTime: ingested.UTC(), Completeness: model.CompletenessComplete, Credential: observation,
		RedactedFields: []string{"raw_json", "process.arguments", "parent.arguments", "ancestors.arguments", "process.environment_variables"}}
	metadata.apply(&event)
	normalizeTetragonContext(&event, source, probe.Parent, probe.Ancestors)
	event.Process.TID = int(tid)
	event.Process.Argv = nil
	for index := range event.Ancestors {
		event.Ancestors[index].Argv = nil
	}
	if !before.complete {
		markPartial(&event, "credential.before")
	}
	if !after.complete {
		markPartial(&event, "credential.after")
	}
	if result == nil {
		markPartial(&event, "credential.return_value")
	}
	if before.snapshot == nil || before.snapshot.UserNamespace.Scope() == "unknown" || after.snapshot == nil || after.snapshot.UserNamespace.Scope() == "unknown" {
		markPartial(&event, "credential.user_namespace_scope")
	}
	stable, _ := json.Marshal(struct {
		ExecID      string
		At          time.Time
		Observation *model.CredentialObservation
	}{source.ExecID, event.EventTime, observation})
	digest := sha256.Sum256(stable)
	event.SourceEventID = "credential:" + hex.EncodeToString(digest[:])
	event.ID = identity.SourceEventID(event.BootID, event.Source, event.Type, event.SourceEventID)
	return event, nil
}

func credentialArgument(argument map[string]json.RawMessage, kind, label string) (json.RawMessage, error) {
	if len(argument) != 2 {
		return nil, ErrUnsupportedEvent
	}
	var actualLabel string
	if json.Unmarshal(argument["label"], &actualLabel) != nil || actualLabel != label {
		return nil, ErrUnsupportedEvent
	}
	raw, exists := argument[kind]
	if !exists || len(raw) == 0 {
		return nil, ErrUnsupportedEvent
	}
	return raw, nil
}

func credentialPositiveInteger(argument map[string]json.RawMessage, kind, label string, bits int) (uint64, error) {
	raw, err := credentialArgument(argument, kind, label)
	if err != nil || len(raw) > 24 {
		return 0, ErrUnsupportedEvent
	}
	text := string(raw)
	if strings.HasPrefix(text, `"`) {
		if json.Unmarshal(raw, &text) != nil {
			return 0, ErrUnsupportedEvent
		}
	}
	value, err := strconv.ParseUint(text, 10, bits)
	if err != nil || value == 0 {
		return 0, ErrUnsupportedEvent
	}
	return value, nil
}
