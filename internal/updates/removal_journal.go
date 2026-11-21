package updates

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/buildinfo"
)

const (
	removalJournal   = "removal.json"
	removalService   = "sentinel-removal.service"
	removalUnit      = "/usr/lib/systemd/system/" + removalService
	stagedRemoval    = "staged"
	armedRemoval     = "armed"
	attemptedRemoval = "attempted"
)

var removalOperationPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,160}$`)

type removalJob struct {
	Order       managed.SignedRemoteRemovalOrder `json:"order"`
	OperationID string                           `json:"operation_id"`
	State       string                           `json:"state"`
	Code        string                           `json:"code,omitempty"`
	Reported    bool                             `json:"reported,omitempty"`
}

func (j *removalJob) report() managed.RemoteRemovalReport {
	return managed.RemoteRemovalReport{OrderID: j.Order.Order.ID, State: j.State, Code: j.Code}
}

func (j *removalJob) validate() error {
	if j.Order.Order.Validate() != nil || !removalOperationPattern.MatchString(j.OperationID) {
		return errors.New("invalid remote removal journal identity")
	}
	switch j.State {
	case stagedRemoval, armedRemoval, attemptedRemoval:
		if j.Code == "" && !j.Reported {
			return nil
		}
	case "failed", "succeeded":
		return j.report().Validate()
	}
	return errors.New("invalid remote removal journal state")
}

func (j *removalJob) reserved(now time.Time) bool {
	return j != nil && (j.State == attemptedRemoval || (j.State == stagedRemoval || j.State == armedRemoval) && now.Before(j.Order.Order.ExpiresAt))
}

func (j *removalJob) matches(agentID, enrollmentID string) bool {
	return j != nil && j.Order.Order.AgentID == agentID && j.Order.Order.EnrollmentID == enrollmentID
}

func (s *Store) readRemoval() (*removalJob, error) {
	path := filepath.Join(s.Directory, removalJournal)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := secureRegular(path, s.OwnerUID, true); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const limit = 16 << 10
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	var job removalJob
	if err := managed.DecodeStrict(data, limit, &job); err != nil || job.validate() != nil {
		return nil, errors.New("invalid remote removal journal")
	}
	return &job, nil
}

func (s *Store) saveRemoval(job *removalJob) error {
	if err := job.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return s.saveJournal(removalJournal, ".removal-", data)
}

// RemoteRemovalSupported only inspects the fixed package components. The
// daemon separately checks host opt-in and canonical paths before advertising.
func RemoteRemovalSupported() bool {
	family, major, arch := HostPlatform("/etc/os-release")
	if os.Geteuid() != 0 || family != "rhel" || (major != "9" && major != "10") || arch != "x86_64" ||
		buildinfo.PackageRelease == "" || buildinfo.PackageArch != arch {
		return false
	}
	if secureRegular(ConfigPath, 0, false) != nil || secureRegular(HelperPath, 0, false) != nil || secureRegular(removalUnit, 0, false) != nil {
		return false
	}
	info, err := os.Stat(HelperPath)
	return err == nil && info.Mode().Perm()&0o100 != 0
}

func (m *Manager) StageRemoteRemoval(ctx context.Context, signed managed.SignedRemoteRemovalOrder, operationID string) error {
	if m.CurrentIdentity == nil {
		return errors.New("remote removal identity unavailable")
	}
	identity, err := m.CurrentIdentity(ctx)
	if err != nil {
		return err
	}
	keys, err := identity.Keys()
	if err != nil {
		return err
	}
	if _, err := managed.VerifyRemoteRemovalOrder(signed, keys, identity.AgentID, identity.EnrollmentID, m.now()); err != nil {
		return err
	}
	start, err := m.stageRemoval(signed, operationID)
	if err != nil || !start {
		return err
	}
	return m.dispatchRemoval(ctx)
}

// Both package actions agree on the lock order. The staging lock prevents the
// update poller from accepting work while a removal is being reserved.
func (m *Manager) stageRemoval(signed managed.SignedRemoteRemovalOrder, operationID string) (bool, error) {
	worker, err := m.Store.lock(".worker.lock")
	if err != nil {
		return false, err
	}
	defer unlock(worker)
	apply, err := m.Store.lock(".apply.lock")
	if err != nil {
		return false, err
	}
	defer unlock(apply)
	update, err := m.Store.Read()
	if err != nil || update != nil && !update.Terminal() {
		if err == nil {
			err = ErrBusy
		}
		return false, err
	}
	current, err := m.Store.readRemoval()
	if err != nil {
		return false, err
	}
	if current.matches(signed.Order.AgentID, signed.Order.EnrollmentID) {
		if current.Order.Order.ID == signed.Order.ID {
			if current.Order.Signature != signed.Signature || current.Order.KeyID != signed.KeyID || current.OperationID != operationID {
				return false, errors.New("conflicting remote removal order")
			}
			return current.State == stagedRemoval || current.State == armedRemoval, nil
		}
		now := m.now()
		if current.reserved(now) || !current.Reported && now.Before(current.Order.Order.ExpiresAt) {
			return false, ErrBusy
		}
	}
	job := &removalJob{Order: signed, OperationID: operationID, State: stagedRemoval}
	if err := m.Store.saveRemoval(job); err != nil {
		return false, err
	}
	return true, nil
}

// RecoverRemoteRemoval cannot execute an unclaimed order. A pre-ACK operation
// may re-report started and an attempted operation only checks the result.
func (m *Manager) RecoverRemoteRemoval(ctx context.Context, identity Identity) error {
	job, err := m.Store.readRemoval()
	if err != nil || job == nil || job.Reported || job.State == stagedRemoval {
		return err
	}
	if !job.matches(identity.AgentID, identity.EnrollmentID) {
		return nil
	}
	return m.dispatchRemoval(ctx)
}

// RemoteRemovalRPMOperation fences RPM preun against a concurrent manual
// authorization and checks that the explicit operation reached the real worker.
// Merely retaining an old journal cannot make a manual erase use a remote grant.
func (m *Manager) RemoteRemovalRPMOperation() (string, error) {
	if m == nil || m.Store == nil {
		return "", nil
	}
	if _, err := os.Lstat(filepath.Join(m.Store.Directory, removalJournal)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	lock, err := m.Store.lock(".apply.lock")
	if errors.Is(err, ErrBusy) {
		job, err := m.Store.readRemoval()
		if err != nil || job == nil || job.State != attemptedRemoval {
			return "", err
		}
		return job.OperationID, nil
	}
	if err != nil {
		return "", err
	}
	unlock(lock)
	return "", nil
}

func (m *Manager) dispatchRemoval(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, err := m.Runner.Run(bounded, "/usr/bin/systemctl", "show", "--all", "--property=LoadState", "--property=FragmentPath", "--property=DropInPaths", removalService)
	if err != nil || !strings.Contains(string(data), "LoadState=loaded\n") || !strings.Contains(string(data), "FragmentPath="+removalUnit+"\n") || !strings.Contains(string(data), "DropInPaths=\n") {
		return errors.New("remote removal service unavailable")
	}
	_, err = m.Runner.Run(bounded, "/usr/bin/systemctl", "start", "--no-block", removalService)
	return err
}
