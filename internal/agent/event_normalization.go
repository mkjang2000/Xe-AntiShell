package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"xe-antishell/internal/detection"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

func (s *Service) normalizeEvent(event *model.Event) error {
	now := time.Now().UTC()
	if event.SchemaVersion == "" {
		event.SchemaVersion = model.SchemaVersion
	}
	if event.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported event schema %q", event.SchemaVersion)
	}
	if event.ID == "" {
		event.ID = identity.NewID("event")
	}
	if event.EventTime.IsZero() {
		event.EventTime = now
		event.Completeness = model.CompletenessPartial
		event.MissingFields = appendUnique(event.MissingFields, "event_time")
	}
	if event.IngestTime.IsZero() {
		event.IngestTime = now
	}
	if event.Type == "" || event.Source == "" {
		return errors.New("event type and source are required")
	}
	if event.HostID == "" {
		event.HostID = s.hostID()
	}
	if event.BootID == "" {
		event.BootID = s.report.Platform.BootID
	}
	if event.StreamID == "" {
		event.StreamID = "process"
	}
	if event.Completeness == "" {
		event.Completeness = model.CompletenessPartial
	}
	if len(event.RawJSON) > 0 && !json.Valid(event.RawJSON) {
		return errors.New("raw_json must contain one valid JSON value")
	}
	if len(event.RawJSON) > 0 && (!s.config.Privacy.StoreRawEvents || s.observationHistoryMinutes() > 0) {
		event.RawJSON = nil
		event.RedactedFields = appendUnique(event.RedactedFields, "raw_json")
	} else if len(event.RawJSON) > s.config.Limits.MaxRawJSON {
		// json.RawMessage cannot safely retain an arbitrary byte prefix: a
		// truncated value would make the enclosing event impossible to encode.
		event.RawJSON = nil
		event.TruncatedFields = appendUnique(event.TruncatedFields, "raw_json")
	}
	s.sanitizeEventPrivacy(event)
	if err := validateOperationEvent(*event); err != nil {
		return err
	}
	if strings.HasPrefix(event.Type, "process.") && event.Process.PID < 1 {
		return errors.New("process event requires a positive PID")
	}
	if len(event.Ancestors) > 64 {
		return errors.New("process ancestry exceeds 64 records")
	}
	for index := range event.Ancestors {
		// Ancestor argv is not needed to attribute a service. Never store
		// opaque source argument strings outside the normal privacy boundary.
		event.Ancestors[index].Argv = nil
		if event.Ancestors[index].FirstSeen.IsZero() {
			event.Ancestors[index].FirstSeen = event.IngestTime
		}
		if event.Ancestors[index].LastSeen.IsZero() {
			event.Ancestors[index].LastSeen = event.IngestTime
		}
		if event.Ancestors[index].StartTime.IsZero() {
			event.Ancestors[index].StartTime = event.EventTime
			event.Completeness = model.CompletenessPartial
			event.MissingFields = appendUnique(event.MissingFields, "ancestors.start_time")
		}
	}
	if event.Sequence > math.MaxInt64 {
		return errors.New("event sequence exceeds the durable integer range")
	}
	sizeProbe := *event
	if sizeProbe.Sequence == 0 {
		// Reserve the largest durable sequence representation so allocation
		// cannot make an already accepted event exceed the configured limit.
		sizeProbe.Sequence = math.MaxInt64
	}
	encoded, err := json.Marshal(sizeProbe)
	if err != nil {
		return fmt.Errorf("encode normalized event: %w", err)
	}
	if len(encoded) > s.config.Limits.MaxEventBytes {
		return fmt.Errorf("normalized event exceeds %d bytes", s.config.Limits.MaxEventBytes)
	}
	if event.Sequence == 0 {
		event.Sequence = s.sequence.Add(1)
	} else {
		for current := s.sequence.Load(); event.Sequence > current; current = s.sequence.Load() {
			if s.sequence.CompareAndSwap(current, event.Sequence) {
				break
			}
		}
	}
	return nil
}

func truncateUTF8(value string, maximum int) string {
	if maximum < 1 || len(value) <= maximum {
		return value
	}
	end := maximum
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}

func redactArguments(arguments []string, sensitiveNames []string) bool {
	sensitive := make(map[string]struct{}, len(sensitiveNames))
	for _, name := range sensitiveNames {
		sensitive[normalizeArgumentName(name)] = struct{}{}
	}
	redacted := false
	redactNext := false
	for index, argument := range arguments {
		if redactNext {
			arguments[index] = "[REDACTED]"
			redacted = true
			redactNext = false
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(argument))
		if strings.HasPrefix(lower, "bearer ") {
			arguments[index] = "Bearer [REDACTED]"
			redacted = true
			continue
		}
		key, _, hasValue := strings.Cut(argument, "=")
		if _, ok := sensitive[normalizeArgumentName(key)]; ok && hasValue {
			arguments[index] = key + "=[REDACTED]"
			redacted = true
			continue
		} else if ok {
			redactNext = true
			continue
		}
		colonKey, _, hasColonValue := strings.Cut(argument, ":")
		if _, ok := sensitive[normalizeArgumentName(colonKey)]; ok && hasColonValue {
			arguments[index] = colonKey + ": [REDACTED]"
			redacted = true
		}
	}
	return redacted
}

func normalizeArgumentName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimLeft(value, "-")
	return strings.ReplaceAll(value, "_", "-")
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// sanitizeEventPrivacy runs before the bounded queue and is safe to repeat.
func (s *Service) sanitizeEventPrivacy(event *model.Event) {
	if len(event.Process.Argv) > s.config.Limits.MaxArgv {
		event.Process.Argv = event.Process.Argv[:s.config.Limits.MaxArgv]
		event.TruncatedFields = appendUnique(event.TruncatedFields, "process.argv")
	}
	for index, argument := range event.Process.Argv {
		if !utf8.ValidString(argument) {
			event.Process.Argv[index] = strings.ToValidUTF8(argument, "�")
			event.TruncatedFields = appendUnique(event.TruncatedFields, "process.argv")
		}
		if len(event.Process.Argv[index]) > s.config.Limits.MaxArgument {
			event.Process.Argv[index] = truncateUTF8(event.Process.Argv[index], s.config.Limits.MaxArgument)
			event.TruncatedFields = appendUnique(event.TruncatedFields, "process.argv")
		}
	}
	detection.SummarizeExecution(event)
	if s.config.Privacy.RedactArgv && redactArguments(event.Process.Argv, s.config.Privacy.SensitiveArgumentNames) {
		event.RedactedFields = appendUnique(event.RedactedFields, "process.argv")
	}

	if isOperationEvent(event.Type) {
		if len(event.RawJSON) != 0 {
			event.RawJSON = nil
			event.RedactedFields = appendUnique(event.RedactedFields, "raw_json")
		}
		event.Process.Argv = nil
	}
}
