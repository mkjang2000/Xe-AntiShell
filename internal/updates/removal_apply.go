package updates

import (
	"context"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/buildinfo"
	"xe-antishell/internal/config"
	"xe-antishell/internal/localapi"
	"xe-antishell/internal/managedclient"
	"xe-antishell/internal/storage"
)

type removalExecutor struct {
	identity Identity
	check    func(context.Context, *removalJob) error
	report   func(context.Context, managed.RemoteRemovalReport) error
	erase    func(context.Context, string) error
	version  string
}

// ApplyRemoteRemoval runs only in the fixed, independent root package service.
// No credential is copied to the worker journal.
func (m *Manager) ApplyRemoteRemoval(ctx context.Context) error {
	if err := secureRegular(ConfigPath, 0, false); err != nil {
		return err
	}
	cfg, err := config.Load(ConfigPath)
	if err != nil || !StandardPaths(cfg.Agent.SocketPath, cfg.Agent.DatabasePath) || secureRegular(cfg.Agent.DatabasePath, 0, true) != nil {
		return errors.New("remote removal identity unavailable")
	}
	state, err := storage.ReadManagedStateForRemoval(ctx, cfg.Agent.DatabasePath)
	if err != nil {
		return errors.New("remote removal identity unavailable")
	}
	client, err := managedclient.New(state.URL, []byte(state.CAPEM), []byte(state.CertificatePEM), []byte(state.KeyPEM))
	if err != nil {
		return errors.New("remote removal identity unavailable")
	}
	defer client.Close()
	executor := removalExecutor{
		identity: Identity{AgentID: state.AgentID, EnrollmentID: state.EnrollmentID, KeyID: state.PolicyKeyID, PublicKey: state.PolicyPublicKey},
		version:  buildinfo.RunningVersion(),
		report:   client.ReportRemoteRemoval,
		erase:    eraseAgentRPM,
		check: func(ctx context.Context, job *removalJob) error {
			if err := secureRegular(ConfigPath, 0, false); err != nil {
				return err
			}
			current, err := config.Load(ConfigPath)
			if err != nil || !current.Central.RemoteRemovalEnabled || current.Agent != cfg.Agent {
				return errors.New("remote removal local gate changed")
			}
			bounded, cancel := context.WithTimeout(ctx, 40*time.Second)
			defer cancel()
			request := struct {
				Order       managed.SignedRemoteRemovalOrder `json:"order"`
				OperationID string                           `json:"operation_id"`
			}{job.Order, job.OperationID}
			return localapi.NewClient(SocketPath).Management(bounded, "remote-removal-check", request, nil)
		},
	}
	return m.applyRemoteRemoval(ctx, executor)
}

func (m *Manager) applyRemoteRemoval(ctx context.Context, executor removalExecutor) error {
	lock, err := m.Store.lock(".apply.lock")
	if err != nil {
		return err
	}
	defer unlock(lock)
	job, err := m.Store.readRemoval()
	if err != nil || job == nil || job.Reported {
		return err
	}
	if !job.matches(executor.identity.AgentID, executor.identity.EnrollmentID) {
		return errors.New("remote removal enrollment changed")
	}
	if job.State == "failed" || job.State == "succeeded" {
		return m.reportRemovalResult(ctx, executor, job)
	}
	if job.State == attemptedRemoval {
		return m.reconcileRemoval(ctx, executor, job)
	}
	return m.beginRemoteRemoval(ctx, executor, job)
}

func (m *Manager) beginRemoteRemoval(ctx context.Context, executor removalExecutor, job *removalJob) error {
	fail := func(code string) error { return m.finishRemoval(ctx, executor, job, "failed", code) }
	keys, err := executor.identity.Keys()
	if err != nil {
		return fail("local_gate")
	}
	verify := func() error {
		_, err := managed.VerifyRemoteRemovalOrder(job.Order, keys, executor.identity.AgentID, executor.identity.EnrollmentID, m.now())
		return err
	}
	if err := verify(); err != nil {
		return fail("local_gate")
	}
	update, err := m.Store.Read()
	if err != nil || update != nil && !update.Terminal() {
		return fail("package_busy")
	}
	installed, err := QueryPackage(ctx, m.Runner, "")
	if err != nil || installed.RunningVersion() != executor.version {
		return fail("package_unavailable")
	}
	if err := executor.check(ctx, job); err != nil {
		return err // The daemon may still be delivering the prerequisite audits.
	}
	job.State = armedRemoval
	if err := m.Store.saveRemoval(job); err != nil {
		return err
	}
	if err := executor.check(ctx, job); err != nil {
		return fail("local_gate")
	}
	current, err := QueryPackage(ctx, m.Runner, "")
	if err != nil || current != installed {
		return fail("package_unavailable")
	}
	if err := verify(); err != nil || ctx.Err() != nil {
		return fail("local_gate")
	}
	// Central reloads the requesting account and revalidates its removal
	// permission for this enrollment's current site before approving execution.
	if err := executor.report(ctx, managed.RemoteRemovalReport{OrderID: job.Order.Order.ID, State: "started"}); err != nil {
		return err
	}
	if err := verify(); err != nil || ctx.Err() != nil {
		return fail("local_gate")
	}
	job.State = attemptedRemoval
	if err := m.Store.saveRemoval(job); err != nil {
		return err
	}
	eraseCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	err = executor.erase(eraseCtx, job.OperationID)
	interrupted := eraseCtx.Err() != nil
	cancel()
	if err != nil {
		if interrupted {
			return fail("interrupted")
		}
		return fail("removal_failed")
	}
	if !m.confirmRemovalAbsence(ctx) {
		return fail("verification_failed")
	}
	return m.finishRemoval(ctx, executor, job, "succeeded", "")
}

func (m *Manager) reconcileRemoval(ctx context.Context, executor removalExecutor, job *removalJob) error {
	if m.confirmRemovalAbsence(ctx) {
		return m.finishRemoval(ctx, executor, job, "succeeded", "")
	}
	return m.finishRemoval(ctx, executor, job, "failed", "interrupted")
}

func eraseAgentRPM(ctx context.Context, operationID string) error {
	if !removalOperationPattern.MatchString(operationID) {
		return errors.New("invalid remote removal operation")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/rpm", "-e", "--", "xe-antishell")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "XEAS_REMOTE_REMOVAL_OPERATION=" + operationID}
	return cmd.Run()
}

// RPM's generic nonzero exit status also covers database failures. Require the
// exact query response and a separate successful read of the underlying RPM DB.
func (m *Manager) confirmRemovalAbsence(ctx context.Context) bool {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	const nameFormat = "%{NAME}\\n"
	result, err := m.Runner.Run(bounded, "/usr/bin/rpm", "-q", "--queryformat", nameFormat, "--", "xe-antishell")
	var status interface{ ExitCode() int }
	if !errors.As(err, &status) || status.ExitCode() != 1 || strings.TrimSpace(string(result)) != "package xe-antishell is not installed" {
		return false
	}
	result, err = m.Runner.Run(bounded, "/usr/bin/rpm", "-q", "--queryformat", nameFormat, "--", "rpm")
	return err == nil && strings.TrimSpace(string(result)) == "rpm"
}

func (m *Manager) finishRemoval(ctx context.Context, executor removalExecutor, job *removalJob, state, code string) error {
	job.State, job.Code = state, code
	if err := m.Store.saveRemoval(job); err != nil {
		return err
	}
	return m.reportRemovalResult(ctx, executor, job)
}

func (m *Manager) reportRemovalResult(ctx context.Context, executor removalExecutor, job *removalJob) error {
	// Keep the worker around briefly after a successful erase: package files
	// are gone by then and a new process cannot replay this report.
	bounded, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	for {
		err := executor.report(bounded, job.report())
		if err == nil {
			job.Reported = true
			return m.Store.saveRemoval(job)
		}
		var status *managedclient.StatusError
		if errors.As(err, &status) && status.Code >= http.StatusBadRequest && status.Code < http.StatusInternalServerError {
			return err
		}
		select {
		case <-bounded.Done():
			return bounded.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
