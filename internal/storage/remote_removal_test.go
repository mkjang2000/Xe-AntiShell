package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestRemoteRemovalRequiresExactOperationAndBothAuditAcknowledgements(t *testing.T) {
	store, private, recovery := removalFixture(t)
	ctx := context.Background()
	order := testRemoteRemovalOrder("order-a")
	op, err := store.PrepareRemoteRemoval(ctx, order)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.PrepareRemoteRemoval(ctx, order)
	if err != nil || retry.ID != op.ID || retry.Challenge != op.Challenge {
		t.Fatalf("retry changed its local binding: %+v %v", retry, err)
	}
	grant := removalGrant(t, private, op, order.ID)
	if _, err := store.AuthorizeRemoval(ctx, op.ID, &grant, ""); err == nil {
		t.Fatal("manual authorization accepted a remote operation")
	}
	if _, err := store.AuthorizeRemoval(ctx, op.ID, nil, recovery); err == nil {
		t.Fatal("offline recovery authorization accepted a remote operation")
	}
	wrongGrant := removalGrant(t, private, op, "different-order")
	if _, err := store.AuthorizeRemoteRemoval(ctx, op.ID, order, wrongGrant); err == nil {
		t.Fatal("grant ID did not bind to its order")
	}
	assertRemovalPrepared(t, store, op.ID)
	authorized, err := store.AuthorizeRemoteRemoval(ctx, op.ID, order, grant)
	if err != nil || authorized.State != "authorized" || authorized.AuditSequence == 0 {
		t.Fatalf("remote authorization: %+v %v", authorized, err)
	}
	if _, err := store.BeginRemoval(ctx); err == nil {
		t.Fatal("generic removal consumed a remote operation")
	}
	if _, err := store.BeginRemoteRemoval(ctx, op.ID, "different-order"); err == nil {
		t.Fatal("mismatched order started removal")
	}
	if _, err := store.BeginRemoteRemoval(ctx, op.ID, order.ID); err == nil {
		t.Fatal("remote removal started before authorization audit acknowledgement")
	}
	ackRemovalAudit(t, store, "removal_authorized", authorized)
	started, err := store.BeginRemoteRemoval(ctx, op.ID, order.ID)
	if err != nil || started.State != "executing" || started.AuditSequence <= authorized.AuditSequence {
		t.Fatalf("remote removal start: %+v %v", started, err)
	}
	if err := store.CheckRemoteRemoval(ctx, op.ID); err == nil {
		t.Fatal("package erasure would begin before removal-start audit acknowledgement")
	}
	ackRemovalAudit(t, store, "removal_started", started)
	if err := store.CheckRemoteRemoval(ctx, op.ID); err != nil {
		t.Fatalf("package gate rejected the acknowledged remote operation: %v", err)
	}
	retry, err = store.BeginRemoteRemoval(ctx, op.ID, order.ID)
	if err != nil || retry.AuditSequence != started.AuditSequence {
		t.Fatalf("repeated preflight changed the existing audit: %+v %v", retry, err)
	}
	policy := managed.DefaultPolicy(order.AgentID, order.EnrollmentID, 1, time.Now())
	policy.UninstallMode = "deny"
	signed, err := managed.SignPolicy(policy, "test-key", private)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SavePolicy(ctx, signed); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckRemoteRemoval(ctx, op.ID); !errors.Is(err, ErrRemovalDenied) {
		t.Fatalf("package gate did not honor the latest deny policy: %v", err)
	}
	if _, err := store.PrepareRemoteRemoval(ctx, testRemoteRemovalOrder("order-b")); !errors.Is(err, ErrRemovalDenied) {
		t.Fatalf("new remote order bypassed the deny policy: %v", err)
	}
}

func TestRemoteRemovalRejectsStaleEnrollmentAndExpiry(t *testing.T) {
	store, private, _ := removalFixture(t)
	ctx := context.Background()
	order := testRemoteRemovalOrder("order-a")
	stale := order
	stale.EnrollmentID = "previous-enrollment"
	if _, err := store.PrepareRemoteRemoval(ctx, stale); err == nil {
		t.Fatal("previous enrollment queued a new removal")
	}
	op, err := store.PrepareRemoteRemoval(ctx, order)
	if err != nil {
		t.Fatal(err)
	}
	grant := removalGrant(t, private, op, order.ID)
	if _, err := store.AuthorizeRemoteRemoval(ctx, op.ID, order, grant); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE remote_removal_operations SET expires_at_ns=? WHERE order_id=?", time.Now().Add(-time.Second).UnixNano(), order.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareRemoteRemoval(ctx, order); err == nil {
		t.Fatal("replay revived the expired local order")
	}
	if _, err := store.BeginRemoteRemoval(ctx, op.ID, order.ID); err == nil {
		t.Fatal("expired order reached preflight")
	}
}

func ackRemovalAudit(t *testing.T, store *Store, action string, op RemovalOperation) {
	t.Helper()
	ctx := context.Background()
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	assertRemovalAudit(t, batch, action, op.ID)
	if err := store.Acknowledge(ctx, managed.Ack{SpoolID: batch.SpoolID, Acknowledged: op.AuditSequence}, batch); err != nil {
		t.Fatal(err)
	}
}

func testRemoteRemovalOrder(id string) managed.RemoteRemovalOrder {
	now := time.Now().UTC()
	return managed.RemoteRemovalOrder{Contract: managed.RemoteRemovalContract, ID: id, AgentID: "removal-agent", EnrollmentID: "removal-enrollment", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
}
