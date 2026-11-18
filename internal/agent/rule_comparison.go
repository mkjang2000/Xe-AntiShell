package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/detection"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

// RuleComparison contains only aggregates from the supplied local sample.
type RuleComparison struct {
	EvaluatedAt time.Time        `json:"evaluated_at"`
	Events      int              `json:"events"`
	EventTypes  map[string]int   `json:"event_types"`
	Rules       []RuleDifference `json:"rules"`
}

type RuleDifference struct {
	ID               string   `json:"id"`
	HasInputType     bool     `json:"has_input_type"`
	Current          int      `json:"current"`
	Candidate        int      `json:"candidate"`
	Added            int      `json:"added"`
	Removed          int      `json:"removed"`
	Changed          int      `json:"changed"`
	AffectedServices []string `json:"affected_services"`
}

type offlineProcesses struct{}

func (offlineProcesses) Snapshot(context.Context, string) ([]model.Process, error) { return nil, nil }
func (offlineProcesses) OriginService(context.Context, int) (string, error)        { return "", nil }

// CompareRules evaluates two standalone configurations in isolation. Neither
// service starts, enrolls, loads a managed policy, or reads the live process tree.
func CompareRules(ctx context.Context, current, candidate config.Config, input io.Reader) (RuleComparison, error) {
	return CompareRulesAt(ctx, current, candidate, input, time.Now())
}

func CompareRulesAt(ctx context.Context, current, candidate config.Config, input io.Reader, at time.Time) (RuleComparison, error) {
	if at.IsZero() {
		return RuleComparison{}, errors.New("comparison evaluation time is required")
	}
	result := RuleComparison{EvaluatedAt: at.UTC(), EventTypes: make(map[string]int)}
	var services [2]*Service
	for i, cfg := range []config.Config{current, candidate} {
		store, err := storage.OpenEphemeral(ctx)
		if err != nil {
			return result, err
		}
		defer store.Close()
		cfg.Privacy.StoreRawEvents = false
		cfg.Response.AllowTerminate = false
		s, err := NewWithProcessSource(cfg, store, nil, offlineProcesses{})
		if err != nil {
			return result, err
		}
		services[i] = s
	}
	if err := replayComparison(ctx, input, services, &result); err != nil {
		return result, err
	}
	before, err := comparisonFindings(ctx, services[0].store)
	if err != nil {
		return result, err
	}
	after, err := comparisonFindings(ctx, services[1].store)
	if err != nil {
		return result, err
	}
	for _, rule := range detection.RuleDefinitions() {
		diff := compareRuleFindings(before[rule.ID], after[rule.ID])
		diff.ID = rule.ID
		for _, kind := range rule.EventTypes {
			if result.EventTypes[kind] > 0 {
				diff.HasInputType = true
				break
			}
		}
		result.Rules = append(result.Rules, diff)
	}
	return result, nil
}

func replayComparison(ctx context.Context, input io.Reader, services [2]*Service, result *RuleComparison) error {
	const maxInput = 16 << 20
	reader := &io.LimitedReader{R: input, N: maxInput + 1}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxInput+1)
	var host, boot string
	for line := 1; scanner.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if reader.N == 0 {
			return errors.New("comparison sample exceeds 16 MiB")
		}
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		if result.Events >= 5000 {
			return errors.New("comparison sample exceeds 5000 observations")
		}
		for i, svc := range services {
			var event model.Event
			if err := json.Unmarshal(raw, &event); err != nil {
				return fmt.Errorf("invalid event JSON at line %d", line)
			}
			if event.EventTime.IsZero() {
				return fmt.Errorf("event_time is required at line %d", line)
			}
			if event.HostID == "" {
				event.HostID = "replay-host"
			}
			if event.BootID == "" {
				event.BootID = "replay-boot"
			}
			if host == "" {
				host, boot = event.HostID, event.BootID
			}
			if host != event.HostID || boot != event.BootID {
				return fmt.Errorf("mixed host or boot at line %d", line)
			}
			if event.ID == "" {
				event.ID = fmt.Sprintf("replay-line-%d", line)
			}
			if event.IngestTime.IsZero() {
				event.IngestTime = event.EventTime
			}
			if err := svc.processObservation(ctx, &event, 0, time.Time{}, result.EvaluatedAt); err != nil {
				return fmt.Errorf("replay line %d: %w", line, err)
			}
			if i == 0 {
				result.EventTypes[event.Type]++
			}
		}
		result.Events++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if reader.N == 0 {
		return errors.New("comparison sample exceeds 16 MiB")
	}
	if result.Events == 0 {
		return errors.New("empty comparison sample")
	}
	return nil
}

func compareRuleFindings(before, after map[string]model.Finding) RuleDifference {
	diff := RuleDifference{Current: len(before), Candidate: len(after), AffectedServices: []string{}}
	affected := make(map[string]bool)
	for key, old := range before {
		f, exists := after[key]
		switch {
		case !exists:
			diff.Removed++
		case f.RuleVersion != old.RuleVersion || f.Severity != old.Severity ||
			f.Confidence != old.Confidence || f.RiskScore != old.RiskScore ||
			f.ResponseDecision != old.ResponseDecision || f.OriginService != old.OriginService ||
			!reflect.DeepEqual(f.RiskFactors, old.RiskFactors):
			diff.Changed++
			affected[f.OriginService] = true
		default:
			continue
		}
		affected[old.OriginService] = true
	}
	for key, f := range after {
		if _, exists := before[key]; !exists {
			diff.Added++
			affected[f.OriginService] = true
		}
	}
	for service := range affected {
		diff.AffectedServices = append(diff.AffectedServices, service)
	}
	sort.Strings(diff.AffectedServices)
	return diff
}

func comparisonFindings(ctx context.Context, store *storage.Store) (map[string]map[string]model.Finding, error) {
	out := make(map[string]map[string]model.Finding)
	q := model.HistoryQuery{Kind: "findings", Limit: 100}
	for {
		page, err := store.History(ctx, q)
		if err != nil {
			return nil, err
		}
		var rows []model.Finding
		if err := json.Unmarshal(page.Items, &rows); err != nil {
			return nil, err
		}
		for _, f := range rows {
			if out[f.RuleID] == nil {
				out[f.RuleID] = make(map[string]model.Finding)
			}
			ids, _ := json.Marshal(f.EvidenceEventIDs)
			out[f.RuleID][string(ids)] = f
		}
		if !page.HasMore {
			return out, nil
		}
		q.Cursor = page.NextCursor
	}
}
