package storage

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func summaryFinding(t *testing.T, store *Store, id string, sequence uint64, when time.Time, severity, state, findingService, processService, summary string) model.Finding {
	t.Helper()
	event := testEvent(id, sequence, when)
	event.Process.PID = int(sequence) + 1000
	event.Process.OriginService = processService
	finding := managedTestFinding(event)
	finding.Severity, finding.State, finding.OriginService, finding.Summary = severity, state, findingService, summary
	if err := store.PersistObservation(context.Background(), event, []model.Finding{finding}); err != nil {
		t.Fatal(err)
	}
	return finding
}

func TestOperatorSummaryCountsRetainedFindingsWindowAndSelfTests(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.FixedZone("KST", 9*3600))
	rows := []struct {
		id                                         string
		age                                        time.Duration
		severity, state, service, process, summary string
	}{
		{"critical", -2 * time.Hour, "critical", "open", "web.service", "web.service", "real"},
		{"old-high", -25 * time.Hour, "high", "open", "web.service", "web.service", "old"},
		{"closed", -time.Hour, "medium", "closed", "web.service", "web.service", "closed"},
		{"boundary", -24 * time.Hour, "low", "open", "web.service", "web.service", "boundary"},
		{"future", time.Hour, "high", "open", "web.service", "web.service", "future"},
		{"self-explicit", -time.Minute, "critical", "open", selfTestService, "other.service", "test"},
		{"self-process", -time.Minute, "critical", "open", "", selfTestService, "test"},
		{"self-legacy", -time.Minute, "critical", "open", "", "", "root shell descended from " + selfTestService},
		{"other-service", -time.Hour, "high", "closed", "other.service", "other.service", "incident mentions " + selfTestService},
	}
	for index, row := range rows {
		summaryFinding(t, store, row.id, uint64(50+index*10000), now.Add(row.age), row.severity, row.state, row.service, row.process, row.summary)
	}
	summary, err := store.OperatorSummary(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalEvents != 9 || summary.Events24H != 7 || summary.TotalFindings != 6 || summary.OpenFindings != 4 || summary.Findings24H != 4 || summary.SelfTestFindings != 3 || summary.CriticalOpen != 1 || summary.HighOpen != 2 || summary.OtherOpen != 1 {
		t.Fatalf("incorrect counts: %+v", summary)
	}
	if !summary.AsOf.Equal(now) || summary.AsOf.Location() != time.UTC || !summary.WindowStart.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("incorrect UTC window: %+v", summary)
	}
	if len(summary.RecentFindings) != 5 || summary.RecentFindings[0].ID != "finding-future" {
		t.Fatalf("recent findings order/bound: %+v", summary.RecentFindings)
	}
	for _, finding := range summary.RecentFindings {
		if finding.OriginService == selfTestService {
			t.Fatal("self-test entered operational recent findings")
		}
	}
}

func TestOperatorSummaryIsNotLimitedToRecentFindingSample(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		summaryFinding(t, store, fmt.Sprintf("real-%d", i), uint64(i+1), now.Add(-2*time.Hour), "high", "open", "web.service", "web.service", "real")
	}
	for i := 0; i < 105; i++ {
		summaryFinding(t, store, fmt.Sprintf("self-%03d", i), uint64(100+i*50), now.Add(-time.Minute), "critical", "open", selfTestService, selfTestService, "test")
	}
	summary, err := store.OperatorSummary(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalFindings != 3 || summary.OpenFindings != 3 || summary.SelfTestFindings != 105 || len(summary.RecentFindings) != 3 {
		t.Fatalf("summary used recent API sample: %+v", summary)
	}
	for _, finding := range summary.RecentFindings {
		if finding.OriginService != "web.service" {
			t.Fatalf("wrong recent service: %+v", finding)
		}
	}
}

func TestOperatorSummaryEmptyStoreIsExplicitAndHasEmptyRecentList(t *testing.T) {
	store, _ := openTestStore(t)
	summary, err := store.OperatorSummary(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalEvents != 0 || summary.OpenFindings != 0 || summary.RecentFindings == nil {
		t.Fatalf("invalid empty summary: %+v", summary)
	}
}

func TestHistorySelfTestFilterKeepsCountsAndCursorScopeConsistent(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Now().UTC()
	for i := 0; i < 13; i++ {
		summaryFinding(t, store, fmt.Sprintf("real-%02d", i), uint64(i+1), now.Add(time.Duration(i)*time.Second), "high", "open", "web.service", "web.service", "real")
	}
	summaryFinding(t, store, "self", 50, now.Add(time.Hour), "critical", "open", selfTestService, selfTestService, "test")
	q := model.HistoryQuery{Kind: "findings", Limit: 10, ExcludeSelfTests: true}
	first, err := store.History(context.Background(), q)
	if err != nil || first.Total != 13 || len(historyIDs(t, "findings", first)) != 10 || !first.HasMore {
		t.Fatalf("filtered first page: %+v %v", first, err)
	}
	q.Cursor = first.NextCursor
	second, err := store.History(context.Background(), q)
	if err != nil || second.Total != 13 || len(historyIDs(t, "findings", second)) != 3 || second.HasMore {
		t.Fatalf("filtered last page: %+v %v", second, err)
	}
	q.ExcludeSelfTests = false
	if _, err := store.History(context.Background(), q); err == nil {
		t.Fatal("cursor accepted after self-test filter changed")
	}
	q.Cursor = ""
	all, err := store.History(context.Background(), q)
	if err != nil || all.Total != 14 {
		t.Fatalf("default compatible history: %+v %v", all, err)
	}
	if !reflect.DeepEqual(historyIDs(t, "findings", all)[0:1], []string{"finding-self"}) {
		t.Fatal("unfiltered history hid self-test")
	}
}
