package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestHistoryEventTypeCombinesFiltersAndBindsCursor(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	for i, kind := range []string{"process.exec", "process.credential_change", "process.credential_change", "process.credential_change", "future.observation", "process.credential_change"} {
		event := testEvent(fmt.Sprintf("typed-%d", i), uint64(i+1), time.Unix(1700000000, 0))
		event.Type, event.Process.OriginService, event.Process.Exe = kind, "worker.service", "/usr/bin/needle"
		if i == 5 {
			event.Process.OriginService = "other.service"
		}
		if err := store.PersistObservation(ctx, event, nil); err != nil {
			t.Fatal(err)
		}
	}
	q := model.HistoryQuery{Kind: "events", EventType: "process.credential_change", Service: "worker.service", Search: "needle", Limit: 2}
	first, err := store.History(ctx, q)
	if err != nil || first.Total != 3 || !first.HasMore || len(historyIDs(t, "events", first)) != 2 {
		t.Fatalf("first typed page: %+v %v", first, err)
	}
	q.Cursor = first.NextCursor
	second, err := store.History(ctx, q)
	if err != nil || second.Total != 3 || second.HasMore || len(historyIDs(t, "events", second)) != 1 {
		t.Fatalf("second typed page: %+v %v", second, err)
	}
	if ids := append(historyIDs(t, "events", first), historyIDs(t, "events", second)...); strings.Join(ids, ",") != "typed-3,typed-2,typed-1" {
		t.Fatalf("typed ordering: %v", ids)
	}
	for _, kind := range []string{"", "process.exec", "future.observation"} {
		q.EventType = kind
		if _, err := store.History(ctx, q); err == nil {
			t.Fatalf("cursor reused with event type %q", kind)
		}
	}
	page, err := store.History(ctx, model.HistoryQuery{Kind: "events", EventType: "future.observation", Limit: 10})
	if err != nil || page.Total != 1 {
		t.Fatalf("future type must remain queryable: %+v %v", page, err)
	}
	page, err = store.History(ctx, model.HistoryQuery{Kind: "events", Limit: 10})
	if err != nil || page.Total != 6 {
		t.Fatalf("empty type must preserve all history: %+v %v", page, err)
	}
}

func TestHistoryRejectsInvalidEventTypeFilters(t *testing.T) {
	store, _ := openTestStore(t)
	for _, q := range []model.HistoryQuery{
		{Kind: "findings", EventType: "process.exec"},
		{Kind: "events", EventType: "process.exec' OR 1=1 --"},
		{Kind: "events", EventType: "process exec"},
		{Kind: "events", EventType: strings.Repeat("a", 129)},
	} {
		if _, err := store.History(context.Background(), q); err == nil {
			t.Fatalf("invalid filter accepted: %+v", q)
		}
	}
}
