package managedclient

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestRemoteRemovalUsesEnrolledTransportAndExactAcknowledgement(t *testing.T) {
	challenge, err := managed.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	order := managed.SignedRemoteRemovalOrder{Order: managed.RemoteRemovalOrder{Contract: managed.RemoteRemovalContract, ID: "order-a", AgentID: "agent", EnrollmentID: "enrollment", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}}
	claim := managed.RemoteRemovalClaim{OrderID: order.Order.ID, OperationID: "operation-a", Challenge: challenge}
	grant := managed.SignedRemovalGrant{Grant: managed.RemovalGrant{ID: order.Order.ID}}
	client := updateClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "agent" {
			t.Error("remote removal did not use the enrolled client certificate")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/remote-removal":
			_ = json.NewEncoder(w).Encode(order)
		case "POST /v1/remote-removal/claim":
			var received managed.RemoteRemovalClaim
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil || received != claim {
				t.Errorf("unexpected remote claim: %+v %v", received, err)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(grant)
		case "POST /v1/remote-removal/report":
			var report managed.RemoteRemovalReport
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil || report.OrderID != order.Order.ID {
				t.Errorf("unexpected remote removal report: %+v %v", report, err)
			}
			if report.State == "started" {
				w.WriteHeader(http.StatusNoContent)
			} else {
				_, _ = w.Write([]byte(`{"mock":"unexpected success status"}`))
			}
		default:
			t.Errorf("unexpected remote removal request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	ctx := context.Background()
	desired, err := client.RemoteRemoval(ctx)
	if err != nil || desired == nil || desired.Order.ID != order.Order.ID {
		t.Fatalf("read remote order: %+v %v", desired, err)
	}
	claimed, err := client.ClaimRemoteRemoval(ctx, claim)
	if err != nil || claimed.Grant.ID != grant.Grant.ID {
		t.Fatalf("claim remote order: %+v %v", claimed, err)
	}
	if err := client.ReportRemoteRemoval(ctx, managed.RemoteRemovalReport{OrderID: order.Order.ID, State: "started"}); err != nil {
		t.Fatalf("acknowledge remote report: %v", err)
	}
	if err := client.ReportRemoteRemoval(ctx, managed.RemoteRemovalReport{OrderID: order.Order.ID, State: "succeeded"}); err == nil {
		t.Fatal("unexpected response treated as a required acknowledgement")
	}
}

func TestRemoteRemovalOlderCentralReturnsNoOrder(t *testing.T) {
	client := updateClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	if order, err := client.RemoteRemoval(context.Background()); err != nil || order != nil {
		t.Fatalf("old central treated as unsupported operation failure: %+v %v", order, err)
	}
}
