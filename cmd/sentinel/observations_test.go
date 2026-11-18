package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"xe-antishell/internal/model"
)

type observationFixture struct {
	query model.ObservationQuery
}

func (f *observationFixture) Observations(ctx context.Context, q model.ObservationQuery) (model.ObservationReport, error) {
	f.query = q
	zero := int64(0)
	return model.ObservationReport{Samples: []model.ObservationSample{
		{EventType: "file.write", Path: "/srv/web/escaped\npath", Outcome: "unknown"},
		{EventType: "network.connect", DestinationAddress: "2001:db8::1", DestinationPort: 443, Outcome: "initiated", ReturnValue: &zero},
	}}, nil
}

func TestObservationCommandOutputAndFilters(t *testing.T) {
	var out bytes.Buffer
	client := &observationFixture{}
	args := []string{"--limit", "3", "--service", "web.service", "--protected-dir", "/srv/web", "--allowed-dir", "/srv/web/uploads"}
	if err := runObservations(context.Background(), client, args, &out, &out, false); err != nil {
		t.Fatal(err)
	}
	if client.query != (model.ObservationQuery{Limit: 3, Service: "web.service", ProtectedDir: "/srv/web", AllowedDir: "/srv/web/uploads"}) {
		t.Fatalf("query = %#v", client.query)
	}
	for _, want := range []string{`/srv/web/escaped\npath`, "[2001:db8::1]:443", "initiated", "unknown"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
	out.Reset()
	if err := runObservations(context.Background(), client, nil, &out, &out, true); err != nil || client.query.Limit != 20 || !strings.Contains(out.String(), `"return_value": 0`) {
		t.Fatalf("json = %q, query = %#v, err = %v", out.String(), client.query, err)
	}
	for _, bad := range [][]string{{"--limit", "0"}, {"--limit", "101"}, {"--protected-dir", "/srv/web"}, {"extra"}} {
		if err := runObservations(context.Background(), client, bad, &out, &out, false); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
