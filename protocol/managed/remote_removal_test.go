package managed

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestRemoteRemovalOrderIsSignedAndEnrollmentBound(t *testing.T) {
	now := time.Now().UTC()
	public, private, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"central": public}
	order := RemoteRemovalOrder{Contract: RemoteRemovalContract, ID: "order-1", AgentID: "web-1", EnrollmentID: "enrollment-1", IssuedAt: now, ExpiresAt: now.Add(MaxRemoteRemovalLifetime)}
	signed, err := SignRemoteRemovalOrder(order, "central", private)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyRemoteRemovalOrder(signed, keys, order.AgentID, order.EnrollmentID, now); err != nil || got != order {
		t.Fatalf("valid order: %+v %v", got, err)
	}
	if _, err := VerifyRemoteRemovalOrder(signed, keys, order.AgentID, "enrollment-2", now); err == nil {
		t.Fatal("accepted another enrollment")
	}
	if _, err := VerifyRemoteRemovalOrder(signed, keys, order.AgentID, order.EnrollmentID, order.ExpiresAt); err == nil {
		t.Fatal("accepted expired order")
	}
	signed.Order.ID = "order-2"
	if _, err := VerifyRemoteRemovalOrder(signed, keys, order.AgentID, order.EnrollmentID, now); err == nil {
		t.Fatal("accepted different order under the first signature")
	}
	signed.Order = order
	signed.Signature, err = signValue("removal", signed.KeyID, order, private, 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRemoteRemovalOrder(signed, keys, order.AgentID, order.EnrollmentID, now); err == nil {
		t.Fatal("accepted a signature from the existing grant domain")
	}
}

func TestRemoteRemovalClaimAndReportAreBounded(t *testing.T) {
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	claim := RemoteRemovalClaim{OrderID: "order-1", OperationID: "operation-1", Challenge: challenge}
	if err := claim.Validate(); err != nil {
		t.Fatal(err)
	}
	claim.Challenge = "short"
	if err := claim.Validate(); err == nil {
		t.Fatal("accepted a malformed challenge")
	}
	for _, report := range []RemoteRemovalReport{
		{OrderID: "order-1", State: "started", Code: "interrupted"},
		{OrderID: "order-1", State: "succeeded", Code: "verification_failed"},
		{OrderID: "order-1", State: "failed"},
		{OrderID: "order-1", State: "failed", Code: "free form"},
	} {
		if err := report.Validate(); err == nil {
			t.Fatalf("accepted report %+v", report)
		}
	}
}
