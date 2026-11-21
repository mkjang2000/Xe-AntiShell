package updates

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type removalTestRunner struct {
	present         bool
	databaseFailure bool
	dispatches      int
}

type removalQueryError int

func (e removalQueryError) ExitCode() int { return int(e) }
func (e removalQueryError) Error() string { return "mock RPM query failed" }

func (r *removalTestRunner) Run(_ context.Context, program string, args ...string) ([]byte, error) {
	switch {
	case program == "/usr/bin/systemctl" && args[0] == "show":
		return []byte("LoadState=loaded\nFragmentPath=" + removalUnit + "\nDropInPaths=\n"), nil
	case program == "/usr/bin/systemctl" && slices.Equal(args, []string{"start", "--no-block", removalService}):
		r.dispatches++
		return nil, nil
	case program == "/usr/bin/rpm" && slices.Equal(args, []string{"-q", "--queryformat", "%{NAME}\\n", "--", "rpm"}):
		if r.databaseFailure {
			return nil, removalQueryError(1)
		}
		return []byte("rpm\n"), nil
	case program == "/usr/bin/rpm" && args[0] == "-q" && args[len(args)-1] == "xe-antishell":
		if !r.present {
			return []byte("package xe-antishell is not installed\n"), removalQueryError(1)
		}
		if args[2] == "%{NAME}\\n" {
			return []byte("xe-antishell\n"), nil
		}
		return []byte("xe-antishell\n0\n0.1.0\n39.el9\nx86_64\n"), nil
	default:
		return nil, errors.New("unexpected command in remote removal test")
	}
}

func removalFixture(t *testing.T) (*Manager, *removalTestRunner, managed.SignedRemoteRemovalOrder, Identity, *time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	identity := Identity{AgentID: "agent-one", EnrollmentID: "enrollment-one", KeyID: "policy-key", PublicKey: managed.EncodePublicKey(public)}
	order, err := managed.SignRemoteRemovalOrder(managed.RemoteRemovalOrder{Contract: managed.RemoteRemovalContract, ID: "order-one", AgentID: identity.AgentID, EnrollmentID: identity.EnrollmentID, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, identity.KeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	runner := &removalTestRunner{present: true}
	manager := &Manager{
		Store: &Store{Directory: filepath.Join(t.TempDir(), "journal"), OwnerUID: uint32(os.Geteuid())},
		Now:   func() time.Time { return now }, Runner: runner,
		CurrentIdentity: func(context.Context) (Identity, error) { return identity, nil },
	}
	return manager, runner, order, identity, &now
}

func TestRemoteRemovalDoesNotEraseWithoutAcknowledgedStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m, runner, order, identity, _ := removalFixture(t)
	const operationID = "op-one"
	if err := m.StageRemoteRemoval(ctx, order, operationID); err != nil || runner.dispatches != 1 {
		t.Fatalf("dispatch after stage = %d, err %v", runner.dispatches, err)
	}
	if state, err := m.RemoteRemovalRPMOperation(); err != nil || state != "" {
		t.Fatalf("staged order permits RPM preun: %q, %v", state, err)
	}
	var transitions []string
	loseACK := true
	erases := 0
	executor := removalExecutor{
		identity: identity,
		version:  "0.1.0-39.el9.x86_64",
		check: func(_ context.Context, job *removalJob) error {
			if job.OperationID != operationID {
				t.Fatalf("unix check used %q", job.OperationID)
			}
			transitions = append(transitions, "gate")
			return nil
		},
		report: func(_ context.Context, report managed.RemoteRemovalReport) error {
			transitions = append(transitions, report.State)
			if report.OrderID != order.Order.ID {
				t.Fatalf("invalid report %#v", report)
			}
			if loseACK {
				loseACK = false
				return errors.New("lost started ACK")
			}
			return nil
		},
		erase: func(_ context.Context, id string) error {
			transitions = append(transitions, "erase")
			attempt, err := m.RemoteRemovalRPMOperation()
			if id != operationID || attempt != id || err != nil {
				t.Fatalf("erase operation = %q, fenced = %q, err %v", id, attempt, err)
			}
			erases++
			runner.present = false
			return nil
		},
	}
	if err := m.applyRemoteRemoval(ctx, executor); err == nil || erases != 0 {
		t.Fatalf("lost ACK invoked RPM: %d, %v", erases, err)
	}
	if err := m.RecoverRemoteRemoval(ctx, identity); err != nil || runner.dispatches != 2 {
		t.Fatalf("dispatch after lost ACK = %d, err %v", runner.dispatches, err)
	}
	if err := m.applyRemoteRemoval(ctx, executor); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(transitions, []string{"gate", "gate", "started", "gate", "gate", "started", "erase", "succeeded"}) {
		t.Fatalf("wrong removal order: %v", transitions)
	}
	job, err := m.Store.readRemoval()
	if err != nil || job.State != "succeeded" || !job.Reported {
		t.Fatalf("no verified result: %#v, %v", job, err)
	}
	if err := m.StageRemoteRemoval(ctx, order, operationID); err != nil || runner.dispatches != 2 {
		t.Fatalf("replayed success dispatched: %d, %v", runner.dispatches, err)
	}
	if err := m.applyRemoteRemoval(ctx, executor); err != nil || erases != 1 {
		t.Fatalf("replayed success erased again: %d, %v", erases, err)
	}
}

func TestRemoteRemovalDetectsFailureAndPreservesAnInterruptedAttempt(t *testing.T) {
	for _, variant := range []struct {
		name, want                                          string
		interrupted, databaseFailure, finalGate, rpmFailure bool
	}{
		{name: "rpm_failure", want: "removal_failed", rpmFailure: true},
		{name: "ambiguous_absence", want: "verification_failed", databaseFailure: true},
		{name: "gate_changed", want: "local_gate", finalGate: true},
		{name: "existing_attempt", want: "interrupted", interrupted: true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m, runner, order, identity, _ := removalFixture(t)
			if err := m.StageRemoteRemoval(ctx, order, "op-one"); err != nil {
				t.Fatal(err)
			}
			if variant.interrupted {
				job, err := m.Store.readRemoval()
				if err != nil {
					t.Fatal(err)
				}
				job.State = attemptedRemoval
				if err := m.Store.saveRemoval(job); err != nil {
					t.Fatal(err)
				}
			}
			var gates, erases int
			var last managed.RemoteRemovalReport
			executor := removalExecutor{
				identity: identity, version: "0.1.0-39.el9.x86_64",
				check: func(context.Context, *removalJob) error {
					gates++
					if variant.finalGate && gates == 2 {
						return errors.New("opt-in revoked")
					}
					return nil
				},
				report: func(_ context.Context, report managed.RemoteRemovalReport) error { last = report; return nil },
				erase: func(context.Context, string) error {
					erases++
					if variant.rpmFailure {
						return errors.New("RPM failed")
					}
					runner.present, runner.databaseFailure = false, variant.databaseFailure
					return nil
				},
			}
			if err := m.applyRemoteRemoval(ctx, executor); err != nil {
				t.Fatal(err)
			}
			if last.State != "failed" || last.Code != variant.want {
				t.Fatalf("got %#v, want failed %q", last, variant.want)
			}
			if (variant.interrupted || variant.finalGate) && erases != 0 {
				t.Fatalf("fenced operation tried erasure: %d", erases)
			}
		})
	}
}

func TestRemoteRemovalFencesConcurrentPackageJobAndExpiredOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m, _, order, _, now := removalFixture(t)
	lock, err := m.Store.lock(".apply.lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.StageRemoteRemoval(ctx, order, "op-one"); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent package job did not fence removal: %v", err)
	}
	unlock(lock)
	*now = order.Order.ExpiresAt
	if err := m.StageRemoteRemoval(ctx, order, "op-one"); err == nil {
		t.Fatal("staged expired order")
	}
}

func TestRemoteRemovalDormantJournalPreservesManualGate(t *testing.T) {
	t.Parallel()
	m, _, order, _, _ := removalFixture(t)
	if err := m.StageRemoteRemoval(context.Background(), order, "op-one"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Store.Directory, removalJournal)
	if err := os.WriteFile(path, []byte("unreadable journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if operation, err := m.RemoteRemovalRPMOperation(); err != nil || operation != "" {
		t.Fatalf("dormant journal blocked manual authorization: %q, %v", operation, err)
	}
	lock, err := m.Store.lock(".apply.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock(lock)
	if operation, err := m.RemoteRemovalRPMOperation(); err == nil || operation != "" {
		t.Fatalf("in-use invalid journal did not fail closed: %q, %v", operation, err)
	}
}

func TestRemoteRemovalOldEnrollmentFencesOnlyWhilePackageLockIsHeld(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m, client, identity, inventory, updateRunner, now := fixture(t)
	old, err := managed.SignRemoteRemovalOrder(managed.RemoteRemovalOrder{
		Contract: managed.RemoteRemovalContract,
		ID:       "previous-order", AgentID: identity.AgentID, EnrollmentID: "previous-enrollment",
		IssuedAt: *now, ExpiresAt: now.Add(time.Minute),
	}, identity.KeyID, client.private)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Store.Prepare(); err != nil {
		t.Fatal(err)
	}
	journal := &removalJob{Order: old, OperationID: "previous-operation", State: attemptedRemoval}
	if err := m.Store.saveRemoval(journal); err != nil {
		t.Fatal(err)
	}
	if err := m.RecoverRemoteRemoval(ctx, identity); err != nil || len(updateRunner.commands) != 0 {
		t.Fatalf("old removal was dispatched: %v, %v", updateRunner.commands, err)
	}
	if err := m.applyRemoteRemoval(ctx, removalExecutor{identity: identity}); err == nil || len(updateRunner.commands) != 0 {
		t.Fatalf("old removal was reconciled using new enrollment: %v, %v", updateRunner.commands, err)
	}
	current, err := managed.SignRemoteRemovalOrder(managed.RemoteRemovalOrder{
		Contract: managed.RemoteRemovalContract,
		ID:       "current-order", AgentID: identity.AgentID, EnrollmentID: identity.EnrollmentID,
		IssuedAt: *now, ExpiresAt: now.Add(time.Minute),
	}, identity.KeyID, client.private)
	if err != nil {
		t.Fatal(err)
	}
	apply, err := m.Store.lock(".apply.lock")
	if err != nil {
		t.Fatal(err)
	}
	updateErr := m.Once(ctx, client, identity, inventory)
	removalErr := m.StageRemoteRemoval(ctx, current, "current-operation")
	unlock(apply)
	if !errors.Is(updateErr, ErrBusy) || !errors.Is(removalErr, ErrBusy) || client.claims != 0 {
		t.Fatalf("new enrollment bypassed active package transaction: update %v, removal %v, claims %d", updateErr, removalErr, client.claims)
	}
	if err := m.Once(ctx, client, identity, inventory); err != nil || client.claims != 1 {
		t.Fatalf("obsolete journal blocked staging: %v, claims %d", err, client.claims)
	}
	if err := m.Apply(ctx); err != nil || updateRunner.installCount != 1 {
		t.Fatalf("obsolete journal blocked applying: %v, installs %d", err, updateRunner.installCount)
	}
	removalRunner := &removalTestRunner{present: true}
	m.Runner = removalRunner
	if err := m.StageRemoteRemoval(ctx, current, "current-operation"); err != nil || removalRunner.dispatches != 1 {
		t.Fatalf("obsolete journal blocked new removal: %v, dispatches %d", err, removalRunner.dispatches)
	}
	newJob, err := m.Store.readRemoval()
	if err != nil || newJob == nil || newJob.Order.Order.ID != current.Order.ID || newJob.State != stagedRemoval {
		t.Fatalf("new generation wasn't reserved: %#v, %v", newJob, err)
	}
}
