package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func historyFixture(t *testing.T) *Store {
	t.Helper()
	store, _ := openTestStore(t)
	when := time.Unix(1700000000, 0).UTC()
	for i := 0; i < 23; i++ {
		event := testEvent(fmt.Sprintf("event-%02d", i), uint64(i+1), when)
		event.Process.PID = 1000 + i
		switch i % 3 {
		case 0:
			event.Process.OriginService = "nginx.service"
		case 1:
			event.Process.OriginService = "php-fpm.service"
		}
		finding := managedTestFinding(event)
		finding.Summary = "ordinary finding"
		finding.Severity = "high"
		if i%2 != 0 {
			finding.Severity = "medium"
		}
		if i == 0 {
			finding.OriginService = "worker.service"
		}
		if i == 7 {
			event.Process.Exe = "/usr/bin/Needle-Target"
			finding.Summary = "Needle-Target %_ literal"
		}
		if err := store.PersistObservation(context.Background(), event, []model.Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func historyIDs(t *testing.T, kind string, page model.HistoryPage) []string {
	t.Helper()
	var ids []string
	if kind == "events" {
		var events []model.Event
		if err := json.Unmarshal(page.Items, &events); err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			ids = append(ids, event.ID)
		}
	} else {
		var findings []model.Finding
		if err := json.Unmarshal(page.Items, &findings); err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			ids = append(ids, finding.ID)
		}
	}
	return ids
}

func TestHistoryPagesHaveStableTieOrderingWithoutOmissions(t *testing.T) {
	store := historyFixture(t)
	for _, kind := range []string{"events", "findings"} {
		t.Run(kind, func(t *testing.T) {
			query := model.HistoryQuery{Kind: kind, Limit: 10}
			var ids []string
			for index, count := range []int{10, 10, 3} {
				page, err := store.History(context.Background(), query)
				if err != nil {
					t.Fatal(err)
				}
				batch := historyIDs(t, kind, page)
				if len(batch) != count || page.Total != 23 || page.HasMore != (index < 2) || (page.NextCursor != "") != (index < 2) {
					t.Fatalf("page %d: count=%d total=%d more=%v cursor=%q", index, len(batch), page.Total, page.HasMore, page.NextCursor)
				}
				ids = append(ids, batch...)
				query.Cursor = page.NextCursor
			}
			var expected []string
			for i := 22; i >= 0; i-- {
				id := fmt.Sprintf("event-%02d", i)
				if kind == "findings" {
					id = "finding-" + id
				}
				expected = append(expected, id)
			}
			if !reflect.DeepEqual(ids, expected) {
				t.Fatalf("tie ordering omitted/duplicated rows: got=%v want=%v", ids, expected)
			}
		})
	}
}

func TestHistoryFiltersIncludeLegacyServiceFallbackAndLiteralSearch(t *testing.T) {
	store := historyFixture(t)
	for _, test := range []struct {
		name  string
		query model.HistoryQuery
		count int
	}{
		{"event service", model.HistoryQuery{Kind: "events", Service: "nginx.service", Limit: 100}, 8},
		{"finding service fallback", model.HistoryQuery{Kind: "findings", Service: "nginx.service", Limit: 100}, 7},
		{"explicit finding service", model.HistoryQuery{Kind: "findings", Service: "worker.service", Limit: 100}, 1},
		{"unknown event service", model.HistoryQuery{Kind: "events", Service: "unknown", Limit: 100}, 7},
		{"unknown finding service", model.HistoryQuery{Kind: "findings", Service: "unknown", Limit: 100}, 7},
		{"high severity", model.HistoryQuery{Kind: "findings", Severity: "high", Limit: 100}, 12},
		{"combined filters", model.HistoryQuery{Kind: "findings", Service: "php-fpm.service", Severity: "high", Limit: 100}, 4},
		{"case insensitive event search", model.HistoryQuery{Kind: "events", Search: "needle-target", Limit: 100}, 1},
		{"case insensitive finding search", model.HistoryQuery{Kind: "findings", Search: "NEEDLE-TARGET", Limit: 100}, 1},
		{"wildcards literal", model.HistoryQuery{Kind: "findings", Search: "%_", Limit: 100}, 1},
		{"SQL text literal", model.HistoryQuery{Kind: "findings", Search: "' OR 1=1 --", Limit: 100}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			page, err := store.History(context.Background(), test.query)
			if err != nil {
				t.Fatal(err)
			}
			if ids := historyIDs(t, test.query.Kind, page); len(ids) != test.count || page.Total != test.count {
				t.Fatalf("filter rows=%v total=%d want=%d", ids, page.Total, test.count)
			}
			if test.query.Kind == "findings" && test.query.Service != "" {
				var findings []model.Finding
				_ = json.Unmarshal(page.Items, &findings)
				for _, finding := range findings {
					if finding.OriginService != test.query.Service {
						t.Fatalf("service fallback omitted from payload: %#v", finding)
					}
				}
			}
		})
	}
	services, err := store.Services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string][2]int{}
	for _, service := range services {
		counts[service.Name] = [2]int{service.EventCount, service.FindingCount}
	}
	expected := map[string][2]int{"nginx.service": {8, 7}, "php-fpm.service": {8, 8}, "unknown": {7, 7}, "worker.service": {0, 1}}
	if !reflect.DeepEqual(counts, expected) {
		t.Fatalf("service counts=%v want=%v", counts, expected)
	}
}

func TestFindingHistorySearchMatchesOperatorTitlesAndProcessPaths(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	when := time.Unix(1700000000, 0).UTC()
	for index, rule := range []string{"web-descendant-root-shell", "web-descendant-shell", "future-rule"} {
		event := testEvent(fmt.Sprintf("operator-search-%d", index), uint64(index+1), when)
		event.Process.PID = 1200 + index
		event.Process.Exe = []string{"/bin/bash", "/bin/sh", "/opt/tool-unknown"}[index]
		finding := managedTestFinding(event)
		finding.RuleID, finding.Summary = rule, "English diagnostic only"
		if index == 2 {
			finding.Summary = "Future raw diagnostic literal %_"
		}
		if err := store.PersistObservation(ctx, event, []model.Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		query string
		ids   []string
	}{
		{"관리자 권한", []string{"finding-operator-search-0"}},
		{"웹 서비스에서 셸 실행", []string{"finding-operator-search-1"}},
		{"/bin/bash", []string{"finding-operator-search-0"}},
		{"/BIN/BASH", []string{"finding-operator-search-0"}},
		{"/opt/tool-unknown", []string{"finding-operator-search-2"}},
		{"future raw diagnostic", []string{"finding-operator-search-2"}},
		{"%_", []string{"finding-operator-search-2"}},
		{"' OR 1=1 --", nil},
	} {
		page, err := store.History(ctx, model.HistoryQuery{Kind: "findings", Search: test.query, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if got := historyIDs(t, "findings", page); !reflect.DeepEqual(got, test.ids) || page.Total != len(test.ids) {
			t.Fatalf("search %q: rows=%v total=%d want=%v", test.query, got, page.Total, test.ids)
		}
	}
	page, err := store.History(ctx, model.HistoryQuery{Kind: "events", Search: "관리자 권한", Limit: 10})
	if err != nil || page.Total != 0 {
		t.Fatalf("finding title leaked into raw event search: %+v %v", page, err)
	}
}

func TestHistoryRejectsInvalidBoundsAndCursorFilterChanges(t *testing.T) {
	store := historyFixture(t)
	for _, query := range []model.HistoryQuery{
		{Kind: "other"}, {Kind: "events", Limit: -1}, {Kind: "events", Limit: 101},
		{Kind: "events", Search: strings.Repeat("x", 257)}, {Kind: "events", Service: strings.Repeat("x", 513)}, {Kind: "events", Cursor: strings.Repeat("x", 2049)}, {Kind: "findings", Severity: "fatal"},
	} {
		if _, err := store.History(context.Background(), query); err == nil {
			t.Fatalf("invalid bounds accepted: %#v", query)
		}
	}
	initial := model.HistoryQuery{Kind: "findings", Limit: 10}
	page, err := store.History(context.Background(), initial)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []model.HistoryQuery{
		{Kind: "events", Cursor: page.NextCursor}, {Kind: "findings", Service: "nginx.service", Cursor: page.NextCursor}, {Kind: "findings", Severity: "high", Cursor: page.NextCursor}, {Kind: "findings", Search: "needle", Cursor: page.NextCursor},
	} {
		if _, err := store.History(context.Background(), query); err == nil {
			t.Fatalf("cursor accepted with different filters: %#v", query)
		}
	}
	data, err := base64.RawURLEncoding.DecodeString(page.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	var cursor historyCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		t.Fatal(err)
	}
	invalid := []string{"bad-base64!", base64.RawURLEncoding.EncodeToString([]byte(`not-json`))}
	for _, mutate := range []func(*historyCursor){func(c *historyCursor) { c.ID = "" }, func(c *historyCursor) { c.Time = 0 }, func(c *historyCursor) { c.Scope = "tampered-scope" }} {
		copy := cursor
		mutate(&copy)
		data, _ := json.Marshal(copy)
		invalid = append(invalid, base64.RawURLEncoding.EncodeToString(data))
	}
	for _, value := range invalid {
		query := initial
		query.Cursor = value
		if _, err := store.History(context.Background(), query); err == nil {
			t.Fatalf("malformed cursor accepted: %q", value)
		}
	}
	// A page-size change is allowed because it does not change the filter scope.
	initial.Cursor, initial.Limit = page.NextCursor, 3
	next, err := store.History(context.Background(), initial)
	if err != nil || len(historyIDs(t, "findings", next)) != 3 {
		t.Fatalf("page size change rejected: %#v error=%v", next, err)
	}
}
