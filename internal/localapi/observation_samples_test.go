package localapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"xe-antishell/internal/model"
)

type sampleBackend struct {
	*fakeBackend
	query model.ObservationQuery
}

func (b *sampleBackend) Observations(_ context.Context, q model.ObservationQuery) (model.ObservationReport, error) {
	b.query = q
	return model.ObservationReport{Samples: []model.ObservationSample{{EventID: "fixture"}}}, nil
}

func TestObservationQueriesRoundTripAndValidate(t *testing.T) {
	b := &sampleBackend{fakeBackend: &fakeBackend{}}
	server := NewServer(b, 100, 1000, 1<<20)
	c := &Client{http: &http.Client{Transport: operatorTransport(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(rec, r)
		return rec.Result(), nil
	})}}
	q := model.ObservationQuery{Service: "unit@a.service", ProtectedDir: "/srv/app", AllowedDir: "/srv/app/cache", Limit: 7}
	got, err := c.Observations(context.Background(), q)
	if err != nil || b.query != q || len(got.Samples) != 1 || got.Samples[0].EventID != "fixture" {
		t.Fatalf("round trip %+v %+v %v", b.query, got, err)
	}
	for _, params := range []string{"limit=-1", "limit=0", "limit=101", "protected_dir=/srv", "allowed_dir=/srv", "protected_dir=relative&service=web", "protected_dir=/srv/../app&service=web", "service=web%00", "protected_dir=/srv&service=unknown"} {
		rec := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/observations?"+params, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("accepted %s: %v", params, rec.Code)
		}
	}
}
