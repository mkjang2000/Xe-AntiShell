package updates

import (
	"context"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"

	"xe-antishell/internal/config"
	"xe-antishell/internal/localapi"
)

func NewManager() *Manager {
	return &Manager{Store: NewStore(), Runner: ExecRunner{}, Now: time.Now, Healthy: RunningTarget, CheckLocal: CheckLocal, CurrentIdentity: ReadLocalIdentity, RunningVersion: ReadRunningVersion, CaptureCollection: CaptureCollection, VerifyCollection: VerifyCollection, Platform: func() (string, string, string) { return HostPlatform("/etc/os-release") }}
}

func StandardPaths(socket, database string) bool {
	return socket == SocketPath && (database == "/var/lib/xe-antishell/sentineld.db" || database == "/var/lib/xe-antishell/sentinel.db")
}

func CheckLocal(ctx context.Context, plan managed.UpdatePlan) error {
	if err := secureRegular(ConfigPath, 0, false); err != nil {
		return err
	}
	cfg, err := config.Load(ConfigPath)
	if err != nil {
		return errors.New("state_unavailable")
	}
	if !cfg.Updates.Enabled {
		return errors.New("disabled")
	}
	if !StandardPaths(cfg.Agent.SocketPath, cfg.Agent.DatabasePath) {
		return errors.New("custom_paths")
	}
	return currentIdentity(ctx, plan)
}

func ReadRunningVersion(ctx context.Context) string {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, err := localapi.NewClient(SocketPath).Status(bounded)
	if err != nil || status.Version == "" {
		return "unknown"
	}
	return status.Version
}

func (m *Manager) running(ctx context.Context) string {
	if m.RunningVersion != nil {
		return m.RunningVersion(ctx)
	}
	return "unknown"
}

func currentIdentity(ctx context.Context, plan managed.UpdatePlan) error {
	identity, err := ReadLocalIdentity(ctx)
	if err != nil {
		return err
	}
	if identity.AgentID != plan.AgentID || identity.EnrollmentID != plan.EnrollmentID {
		return errors.New("target_mismatch")
	}
	return nil
}

func ReadLocalIdentity(ctx context.Context) (Identity, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var identity Identity
	if err := localapi.NewClient(SocketPath).Management(bounded, "update-identity", nil, &identity); err != nil {
		return identity, errors.New("identity_unavailable")
	}
	return identity, nil
}

// The live daemon must identify the target build. Collector degradation is
// reported separately and does not turn an otherwise working update into failure.
func RunningTarget(ctx context.Context, plan managed.UpdatePlan) bool {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, err := localapi.NewClient(SocketPath).Status(bounded)
	return err == nil && status.Version == PackageVersion(plan.Release.Package) && !status.StartedAt.IsZero() && currentIdentity(bounded, plan) == nil
}
