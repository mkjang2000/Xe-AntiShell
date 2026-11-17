package collector

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const (
	defaultAuditMaxPending = 4096
	defaultAuditMaxRecords = 64
	defaultAuditMaxBytes   = 256 << 10
	defaultAuditTimeout    = 2 * time.Second
)

var ErrInvalidAuditRecord = errors.New("invalid audit record")

type AuditAssemblerOptions struct {
	MaxPending         int
	MaxRecords         int
	MaxBytes           int
	Timeout            time.Duration
	Metadata           Metadata
	IncludeExecutables []string
}

// AuditAssembler reconstructs audit events whose SYSCALL, EXECVE, CWD and EOE
// records can arrive interleaved. It is not safe for concurrent use; an audit
// dispatcher should feed it from its single ordered reader goroutine.
type AuditAssembler struct {
	options            AuditAssemblerOptions
	pending            map[uint64]*auditGroup
	includeExecutables map[string]struct{}
}

type auditGroup struct {
	serial    uint64
	eventTime time.Time
	firstSeen time.Time
	lastSeen  time.Time
	records   []auditRecord
	bytes     int
	truncated bool
}

type auditRecord struct {
	typeName string
	raw      string
	fields   map[string]string
	quoted   map[string]bool
}

func NewAuditAssembler(options AuditAssemblerOptions) *AuditAssembler {
	if options.MaxPending <= 0 {
		options.MaxPending = defaultAuditMaxPending
	}
	if options.MaxRecords <= 0 {
		options.MaxRecords = defaultAuditMaxRecords
	}
	if options.MaxBytes <= 0 {
		options.MaxBytes = defaultAuditMaxBytes
	}
	if options.Timeout <= 0 {
		options.Timeout = defaultAuditTimeout
	}
	includeExecutables := make(map[string]struct{}, len(options.IncludeExecutables))
	for _, executable := range options.IncludeExecutables {
		executable = strings.TrimSpace(executable)
		if executable != "" {
			includeExecutables[executable] = struct{}{}
		}
	}
	return &AuditAssembler{
		options:            options,
		pending:            make(map[uint64]*auditGroup),
		includeExecutables: includeExecutables,
	}
}

// Feed may return an expired/evicted event before the event completed by the
// current record. Malformed records do not discard already expired events.
func (a *AuditAssembler) Feed(line string, receivedAt time.Time) ([]model.Event, error) {
	events := a.FlushExpired(receivedAt)
	record, serial, eventTime, err := parseAuditRecord(line)
	if err != nil {
		return events, err
	}
	group, exists := a.pending[serial]
	if !exists {
		if len(a.pending) >= a.options.MaxPending {
			oldest := a.oldestGroup()
			if oldest != nil {
				oldest.truncated = true
				if event, ok := a.normalize(oldest, receivedAt, false); ok {
					events = append(events, event)
				}
				delete(a.pending, oldest.serial)
			}
		}
		group = &auditGroup{serial: serial, eventTime: eventTime, firstSeen: receivedAt}
		a.pending[serial] = group
	}
	group.lastSeen = receivedAt
	if group.eventTime.IsZero() {
		group.eventTime = eventTime
	}
	if len(group.records) >= a.options.MaxRecords || group.bytes+len(line) > a.options.MaxBytes {
		group.truncated = true
	} else {
		group.records = append(group.records, record)
		group.bytes += len(line)
	}
	if record.typeName == "EOE" {
		if event, ok := a.normalize(group, receivedAt, true); ok {
			events = append(events, event)
		}
		delete(a.pending, serial)
	}
	return events, nil
}

func (a *AuditAssembler) FlushExpired(now time.Time) []model.Event {
	var expired []*auditGroup
	for _, group := range a.pending {
		if now.Sub(group.lastSeen) >= a.options.Timeout {
			expired = append(expired, group)
		}
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i].serial < expired[j].serial })
	events := make([]model.Event, 0, len(expired))
	for _, group := range expired {
		if event, ok := a.normalize(group, now, false); ok {
			events = append(events, event)
		}
		delete(a.pending, group.serial)
	}
	return events
}

func (a *AuditAssembler) FlushAll(now time.Time) []model.Event {
	groups := make([]*auditGroup, 0, len(a.pending))
	for _, group := range a.pending {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].serial < groups[j].serial })
	events := make([]model.Event, 0, len(groups))
	for _, group := range groups {
		if event, ok := a.normalize(group, now, false); ok {
			events = append(events, event)
		}
		delete(a.pending, group.serial)
	}
	return events
}

func (a *AuditAssembler) Pending() int { return len(a.pending) }

func (a *AuditAssembler) oldestGroup() *auditGroup {
	var oldest *auditGroup
	for _, group := range a.pending {
		if oldest == nil || group.firstSeen.Before(oldest.firstSeen) {
			oldest = group
		}
	}
	return oldest
}

func parseAuditRecord(line string) (auditRecord, uint64, time.Time, error) {
	line = strings.TrimSpace(line)
	typeIndex, msgIndex := strings.Index(line, "type="), strings.Index(line, "msg=audit(")
	if typeIndex < 0 || msgIndex < 0 {
		return auditRecord{}, 0, time.Time{}, ErrInvalidAuditRecord
	}
	typeStart := typeIndex + len("type=")
	typeLength := strings.IndexByte(line[typeStart:], ' ')
	if typeLength < 0 {
		return auditRecord{}, 0, time.Time{}, ErrInvalidAuditRecord
	}
	typeName := line[typeStart : typeStart+typeLength]
	headerStart := msgIndex + len("msg=audit(")
	headerLength := strings.Index(line[headerStart:], "):")
	if headerLength < 0 {
		return auditRecord{}, 0, time.Time{}, ErrInvalidAuditRecord
	}
	header := line[headerStart : headerStart+headerLength]
	separator := strings.LastIndexByte(header, ':')
	if separator < 0 {
		return auditRecord{}, 0, time.Time{}, ErrInvalidAuditRecord
	}
	serial, err := strconv.ParseUint(header[separator+1:], 10, 64)
	if err != nil {
		return auditRecord{}, 0, time.Time{}, fmt.Errorf("%w: serial: %v", ErrInvalidAuditRecord, err)
	}
	eventTime, err := parseAuditTime(header[:separator])
	if err != nil {
		return auditRecord{}, 0, time.Time{}, fmt.Errorf("%w: timestamp: %v", ErrInvalidAuditRecord, err)
	}
	bodyStart := headerStart + headerLength + len("):")
	fields, quoted := parseAuditFields(line[bodyStart:])
	return auditRecord{typeName: typeName, raw: line, fields: fields, quoted: quoted}, serial, eventTime, nil
}

func parseAuditTime(value string) (time.Time, error) {
	parts := strings.SplitN(value, ".", 2)
	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	nanoseconds := int64(0)
	if len(parts) == 2 {
		fraction := parts[1]
		if len(fraction) > 9 {
			fraction = fraction[:9]
		}
		fraction += strings.Repeat("0", 9-len(fraction))
		nanoseconds, err = strconv.ParseInt(fraction, 10, 64)
		if err != nil {
			return time.Time{}, err
		}
	}
	return time.Unix(seconds, nanoseconds).UTC(), nil
}

func parseAuditFields(input string) (map[string]string, map[string]bool) {
	fields := make(map[string]string)
	quoted := make(map[string]bool)
	for index := 0; index < len(input); {
		for index < len(input) && input[index] == ' ' {
			index++
		}
		start := index
		for index < len(input) && input[index] != '=' && input[index] != ' ' {
			index++
		}
		if index >= len(input) || input[index] != '=' {
			for index < len(input) && input[index] != ' ' {
				index++
			}
			continue
		}
		key := input[start:index]
		index++
		valueStart := index
		if index < len(input) && input[index] == '"' {
			quoted[key] = true
			index++
			escaped := false
			for index < len(input) {
				if input[index] == '"' && !escaped {
					index++
					break
				}
				escaped = input[index] == '\\' && !escaped
				if input[index] != '\\' {
					escaped = false
				}
				index++
			}
		} else {
			for index < len(input) && input[index] != ' ' {
				index++
			}
		}
		fields[key] = unquoteAuditValue(input[valueStart:index])
	}
	return fields, quoted
}

func unquoteAuditValue(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		if decoded, err := strconv.Unquote(value); err == nil {
			return decoded
		}
		return strings.Trim(value, "\"")
	}
	return value
}

func decodeAuditArgument(value string, encoded bool) string {
	if encoded && len(value) >= 2 && len(value)%2 == 0 && isHex(value) {
		if decoded, err := hex.DecodeString(value); err == nil {
			if utf8.Valid(decoded) && printableAuditBytes(decoded) {
				return strings.ReplaceAll(string(decoded), "\x00", " ")
			}
		}
	}
	return value
}

func printableAuditBytes(value []byte) bool {
	for _, b := range value {
		if b == 0 || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func isHex(value string) bool {
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func (a *AuditAssembler) normalize(group *auditGroup, ingestTime time.Time, complete bool) (model.Event, bool) {
	event := model.Event{
		SchemaVersion: model.SchemaVersion,
		StreamID:      "process",
		Source:        "audit",
		SourceEventID: strconv.FormatUint(group.serial, 10),
		Type:          "process.exec",
		EventTime:     group.eventTime,
		IngestTime:    ingestTime.UTC(),
		Completeness:  model.CompletenessPartial,
		Process: model.Process{
			ExecID: "audit:" + strconv.FormatUint(group.serial, 10),
			PID:    -1, PPID: -1, UID: -1, EUID: -1, GID: -1, EGID: -1,
			LineageConfidence: model.LineageInferred,
		},
	}
	a.options.Metadata.apply(&event)
	event.ID = identity.SourceEventID(event.BootID, event.Source, event.Type, event.SourceEventID)
	argvByIndex := make(map[int]string)
	var rawRecords []string
	foundExec, foundSyscall := false, false
	for _, record := range group.records {
		rawRecords = append(rawRecords, record.raw)
		switch record.typeName {
		case "EXECVE":
			foundExec = true
			for key, value := range record.fields {
				if len(key) < 2 || key[0] != 'a' {
					continue
				}
				index, err := strconv.Atoi(key[1:])
				if err == nil {
					argvByIndex[index] = decodeAuditArgument(value, !record.quoted[key])
				}
			}
		case "SYSCALL":
			foundSyscall = true
			event.Process.PID = auditInt(record.fields["pid"])
			event.Process.PPID = auditInt(record.fields["ppid"])
			event.Process.UID = auditCredential(record.fields["uid"])
			event.Process.EUID = auditCredential(record.fields["euid"])
			event.Process.GID = auditCredential(record.fields["gid"])
			event.Process.EGID = auditCredential(record.fields["egid"])
			event.Process.Exe = record.fields["exe"]
		case "CWD":
			event.Process.CWD = record.fields["cwd"]
		}
	}
	if !foundExec {
		return model.Event{}, false
	}
	indexes := make([]int, 0, len(argvByIndex))
	for index := range argvByIndex {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	for _, index := range indexes {
		event.Process.Argv = append(event.Process.Argv, argvByIndex[index])
	}
	if event.Process.Exe == "" && len(event.Process.Argv) != 0 {
		event.Process.Exe = event.Process.Argv[0]
	}
	if len(a.includeExecutables) != 0 {
		if _, included := a.includeExecutables[filepath.Base(event.Process.Exe)]; !included {
			return model.Event{}, false
		}
	}
	event.Process.StartTime = event.EventTime
	event.Process.FirstSeen, event.Process.LastSeen = event.IngestTime, event.IngestTime
	event.Process.Key = identity.ProcessKey(event.BootID, event.Process, event.EventTime)
	if !foundSyscall {
		event.MissingFields = append(event.MissingFields, "audit.SYSCALL")
	}
	if event.Process.PID < 0 {
		event.MissingFields = append(event.MissingFields, "process.pid")
	}
	if event.Process.Exe == "" {
		event.MissingFields = append(event.MissingFields, "process.exe")
	}
	if !complete {
		event.MissingFields = append(event.MissingFields, "audit.EOE")
	}
	if group.truncated {
		event.TruncatedFields = append(event.TruncatedFields, "audit.records")
	}
	if complete && foundSyscall && !group.truncated {
		event.Completeness = model.CompletenessComplete
	}
	event.RawJSON, _ = json.Marshal(rawRecords)
	return event, true
}

func auditInt(value string) int {
	if value == "" {
		return -1
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return parsed
}

func auditCredential(value string) int64 {
	if value == "" || value == "4294967295" {
		return -1
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return -1
	}
	return parsed
}
