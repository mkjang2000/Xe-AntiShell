package storage

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/managed"
)

func TestRemovalRejectsInvalidGrantWithoutConsumingOperation(t *testing.T) {
	for _, scenario := range []string{"wrong-host", "wrong-enrollment", "wrong-challenge", "expired", "future", "tampered", "untrusted-key"} {
		t.Run(scenario, func(t *testing.T) {
			store, private, _ := removalFixture(t)
			ctx := context.Background()
			op, err := store.CreateRemoval(ctx)
			if err != nil {
				t.Fatal(err)
			}
			signed := removalGrant(t, private, op, "grant-a")
			grant := signed.Grant
			switch scenario {
			case "wrong-host":
				grant.AgentID = "another-agent"
			case "wrong-enrollment":
				grant.EnrollmentID = "another-enrollment"
			case "wrong-challenge":
				grant.Challenge, err = managed.NewChallenge()
			case "expired":
				grant.IssuedAt, grant.ExpiresAt = time.Now().Add(-2*time.Minute), time.Now().Add(-time.Minute)
			case "future":
				grant.IssuedAt, grant.ExpiresAt = time.Now().Add(2*time.Minute), time.Now().Add(5*time.Minute)
			}
			if err != nil {
				t.Fatal(err)
			}
			signed, err = managed.SignRemovalGrant(grant, "test-key", private)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "tampered" {
				signed.Grant.ID = "changed-after-signing"
			} else if scenario == "untrusted-key" {
				signed.KeyID = "untrusted"
			}
			if _, err := store.AuthorizeRemoval(ctx, op.ID, &signed, ""); err == nil {
				t.Fatal("invalid grant authorized removal")
			}
			assertRemovalPrepared(t, store, op.ID)
			valid := removalGrant(t, private, op, "valid-after-rejection")
			if _, err := store.AuthorizeRemoval(ctx, op.ID, &valid, ""); err != nil {
				t.Fatalf("rejected grant consumed operation: %v", err)
			}
		})
	}
}

func TestOrdinaryRemovalRequiresCentralAuditACKAndResumesSafely(t *testing.T) {
	store, private, _ := removalFixture(t)
	ctx := context.Background()
	if _, err := store.BeginRemoval(ctx); err == nil {
		t.Fatal("removal began without authorization")
	}
	op, err := store.CreateRemoval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signed := removalGrant(t, private, op, "single-use-grant")
	authorized, err := store.AuthorizeRemoval(ctx, op.ID, &signed, "")
	if err != nil || authorized.State != "authorized" || authorized.AuditSequence == 0 || authorized.AuthorizedAt == nil {
		t.Fatalf("authorize: %#v, %v", authorized, err)
	}
	before, err := store.DeliveryStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.AuthorizeRemoval(ctx, op.ID, &signed, "")
	if err != nil || retry.AuditSequence != authorized.AuditSequence {
		t.Fatalf("lost authorization reply must be safely repeatable: %#v, %v", retry, err)
	}
	after, err := store.DeliveryStatus(ctx)
	if err != nil || after.Pending != before.Pending {
		t.Fatalf("authorization retry duplicated delivery obligation: %#v, %v", after, err)
	}
	if _, err := store.BeginRemoval(ctx); err == nil || !strings.Contains(err.Error(), "acknowledged") {
		t.Fatalf("ordinary removal bypassed remote audit ACK: %v", err)
	}
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	assertRemovalAudit(t, batch, "removal_requested", op.ID)
	assertRemovalAudit(t, batch, "removal_authorized", op.ID)
	if err := store.Acknowledge(ctx, managed.Ack{SpoolID: batch.SpoolID, Acknowledged: authorized.AuditSequence}, batch); err != nil {
		t.Fatal(err)
	}
	executing, err := store.BeginRemoval(ctx)
	if err != nil || executing.State != "executing" || executing.AuditSequence <= authorized.AuditSequence {
		t.Fatalf("begin after ACK: %#v, %v", executing, err)
	}
	repeated, err := store.BeginRemoval(ctx)
	if err != nil || repeated.ID != op.ID || repeated.AuditSequence != executing.AuditSequence {
		t.Fatalf("lost begin reply must safely resume without another ACK or audit: %#v, %v", repeated, err)
	}
	batch, err = store.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	assertRemovalAudit(t, batch, "removal_started", op.ID)
	second, err := store.CreateRemoval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rebound := removalGrant(t, private, second, signed.Grant.ID)
	if _, err := store.AuthorizeRemoval(ctx, second.ID, &rebound, ""); err == nil {
		t.Fatal("single-use grant ID was replayed against a new signed challenge")
	}
}

func TestRecoveryOverridesDenyPolicyOfflineAndIsConsumedOnce(t *testing.T) {
	store, private, recovery := removalFixture(t)
	ctx := context.Background()
	policy := managed.DefaultPolicy("removal-agent", "removal-enrollment", 1, time.Now())
	policy.UninstallMode = "deny"
	signedPolicy, err := managed.SignPolicy(policy, "test-key", private)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SavePolicy(ctx, signedPolicy); err != nil {
		t.Fatal(err)
	}
	op, err := store.CreateRemoval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signed := removalGrant(t, private, op, "policy-denied")
	if _, err := store.AuthorizeRemoval(ctx, op.ID, &signed, ""); err == nil || !strings.Contains(err.Error(), "policy denies") {
		t.Fatalf("ordinary grant bypassed deny policy: %v", err)
	}
	if _, err := store.AuthorizeRemoval(ctx, op.ID, nil, recovery+"invalid"); err == nil {
		t.Fatal("invalid recovery code authorized removal")
	}
	if _, err := store.AuthorizeRemoval(ctx, op.ID, &signed, recovery); err == nil {
		t.Fatal("ambiguous dual authorization was accepted")
	}
	authorized, err := store.AuthorizeRemoval(ctx, op.ID, nil, recovery)
	if err != nil || authorized.Mode != "recovery" {
		t.Fatalf("offline recovery under deny policy: %#v, %v", authorized, err)
	}
	status, err := store.DeliveryStatus(ctx)
	if err != nil || status.Acknowledged != 0 {
		t.Fatalf("recovery fixture must remain offline/unacknowledged: %#v, %v", status, err)
	}
	if _, err := store.BeginRemoval(ctx); err != nil {
		t.Fatalf("offline recovery required central availability: %v", err)
	}
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	assertRemovalAudit(t, batch, "removal_authorized", op.ID)
	assertRemovalAudit(t, batch, "removal_started", op.ID)
	other, err := store.CreateRemoval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthorizeRemoval(ctx, other.ID, nil, recovery); err == nil {
		t.Fatal("recovery code was reused for another removal operation")
	}
}

func TestRemovalExpiredOperationAndAuthorization(t *testing.T) {
	for _, phase := range []string{"operation", "authorization"} {
		t.Run(phase, func(t *testing.T) {
			store, private, _ := removalFixture(t)
			ctx := context.Background()
			op, err := store.CreateRemoval(ctx)
			if err != nil {
				t.Fatal(err)
			}
			signed := removalGrant(t, private, op, "expiration-grant")
			old := time.Now().Add(-managed.MaxRemovalGrantLifetime - time.Minute).UnixNano()
			if phase == "operation" {
				if _, err := store.db.Exec("UPDATE removal_operations SET created_at_ns=? WHERE operation_id=?", old, op.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := store.AuthorizeRemoval(ctx, op.ID, &signed, ""); err == nil || !strings.Contains(err.Error(), "expired") {
					t.Fatalf("expired operation was authorized: %v", err)
				}
				return
			}
			if _, err := store.AuthorizeRemoval(ctx, op.ID, &signed, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec("UPDATE removal_operations SET authorized_at_ns=? WHERE operation_id=?", old, op.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.BeginRemoval(ctx); err == nil || !strings.Contains(err.Error(), "expired") {
				t.Fatalf("expired authorization was executed: %v", err)
			}
		})
	}
}

func TestRemovalAuthorizationRollsBackIfAuditCannotPersist(t *testing.T) {
	store, private, _ := removalFixture(t)
	ctx := context.Background()
	op, err := store.CreateRemoval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signed := removalGrant(t, private, op, "transaction-grant")
	if _, err := store.db.Exec(`CREATE TRIGGER reject_removal_audit BEFORE INSERT ON delivery_outbox WHEN json_extract(NEW.payload,'$.action')='removal_authorized' BEGIN SELECT RAISE(ABORT,'test removal audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthorizeRemoval(ctx, op.ID, &signed, ""); err == nil {
		t.Fatal("authorization survived failed durable audit insertion")
	}
	assertRemovalPrepared(t, store, op.ID)
	if _, err := store.db.Exec("DROP TRIGGER reject_removal_audit"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthorizeRemoval(ctx, op.ID, &signed, ""); err != nil {
		t.Fatalf("rolled-back audit attempt burned the grant: %v", err)
	}
}

func removalFixture(t *testing.T) (*Store, ed25519.PrivateKey, string) {
	t.Helper()
	store, _ := openTestStore(t)
	public, private, err := managed.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	recovery, verifier, err := managed.GenerateRecoveryCode("removal-agent", "removal-enrollment")
	if err != nil {
		t.Fatal(err)
	}
	state := ManagedState{AgentID: "removal-agent", EnrollmentID: "removal-enrollment", KeyPEM: "test-private-key", PolicyKeyID: "test-key", PolicyPublicKey: managed.EncodePublicKey(public), Recovery: verifier}
	if err := store.SaveManagedState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	return store, private, recovery
}

func removalGrant(t *testing.T, private ed25519.PrivateKey, operation RemovalOperation, id string) managed.SignedRemovalGrant {
	t.Helper()
	now := time.Now().UTC()
	grant := managed.RemovalGrant{ID: id, AgentID: "removal-agent", EnrollmentID: "removal-enrollment", Challenge: operation.Challenge, Action: "uninstall", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	signed, err := managed.SignRemovalGrant(grant, "test-key", private)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func assertRemovalPrepared(t *testing.T, store *Store, id string) {
	t.Helper()
	op, err := store.Removal(context.Background(), id)
	if err != nil || op.State != "prepared" || op.AuthorizationID != "" || op.AuditSequence != 0 {
		t.Fatalf("failed authorization changed operation: %#v, %v", op, err)
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM consumed_authorizations WHERE operation_id=?", id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed authorization consumed a grant: %d, %v", count, err)
	}
}

func assertRemovalAudit(t *testing.T, batch managed.Batch, action, operation string) {
	t.Helper()
	count := 0
	for _, record := range batch.Records {
		if record.Kind != managed.RecordKindAudit {
			continue
		}
		var audit managed.AuditRecord
		if err := json.Unmarshal(record.Payload, &audit); err != nil {
			t.Fatal(err)
		}
		if audit.Action == action && audit.OperationID == operation {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("audit %s for %s: found %d, want exactly one durable record", action, operation, count)
	}
}
