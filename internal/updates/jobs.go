package updates

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type Job struct {
	SchemaVersion int                                `json:"schema_version"`
	Plan          managed.SignedUpdatePlan           `json:"plan"`
	Authorization *managed.SignedUpdateAuthorization `json:"authorization,omitempty"`
	KeyID         string                             `json:"key_id"`
	PublicKey     string                             `json:"public_key"`
	Collection    CollectionBaseline                 `json:"collection_baseline"`
	Reports       []managed.UpdateReport             `json:"reports"`
	Acknowledged  uint64                             `json:"acknowledged"`
}

func (j *Job) Last() managed.UpdateReport {
	if len(j.Reports) == 0 {
		return managed.UpdateReport{}
	}
	return j.Reports[len(j.Reports)-1]
}
func (j *Job) Terminal() bool { return j.Last().State == "succeeded" || j.Last().State == "failed" }
func (j *Job) Append(state, code, version string, installed *managed.RPMPackage, now time.Time) {
	last := j.Last()
	if last.State == state && last.ErrorCode == code {
		return
	}
	r := managed.UpdateReport{ProtocolVersion: managed.UpdateProtocolVersion, JobID: j.Plan.Plan.JobID, EnrollmentID: j.Plan.Plan.EnrollmentID, Revision: j.Plan.Plan.Revision, Sequence: uint64(len(j.Reports) + 1), State: state, ErrorCode: code, RunningVersion: version, InstalledPackage: installed, ObservedAt: now.UTC()}
	if state == "succeeded" && !j.Collection.Active {
		r.CollectionCheck = "not_applicable"
	}
	j.Reports = append(j.Reports, r)
}

// Store is the updater's journal, not the daemon's SQLite database. It contains
// only public pinned identity, signed commands and bounded result metadata.
type Store struct {
	Directory string
	OwnerUID  uint32
}

func NewStore() *Store { return &Store{Directory: Directory} }

func secureRegular(path string, owner uint32, private bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("state_unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner || info.Mode().Perm()&0o022 != 0 || private && info.Mode().Perm()&0o077 != 0 || stat.Nlink != 1 {
		return errors.New("state_unavailable")
	}
	return nil
}

func (s *Store) Prepare() error {
	if !filepath.IsAbs(s.Directory) || filepath.Clean(s.Directory) == "/" {
		return errors.New("state_unavailable")
	}
	// All path components must be trusted. A sticky /tmp is allowed only as
	// an ancestor of private temporary roots used by tests.
	for path := s.Directory; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && path == s.Directory {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("state_unavailable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != s.OwnerUID || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("state_unavailable")
		}
		if path == "/" {
			break
		}
	}
	if err := os.Mkdir(s.Directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("state_unavailable")
	}
	info, err := os.Lstat(s.Directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		return errors.New("state_unavailable")
	}
	return nil
}

func (s *Store) lock(name string) (*os.File, error) {
	if err := s.Prepare(); err != nil {
		return nil, err
	}
	path := filepath.Join(s.Directory, name)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("state_unavailable")
	}
	if err := secureRegular(path, s.OwnerUID, true); err != nil {
		file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, ErrBusy
	}
	return file, nil
}
func unlock(file *os.File) { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }

func (s *Store) read() (*Job, error) {
	path := filepath.Join(s.Directory, "job.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := secureRegular(path, s.OwnerUID, true); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("state_unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 256<<10+1))
	if err != nil || len(data) > 256<<10 {
		return nil, errors.New("state_unavailable")
	}
	var job Job
	if managed.DecodeStrict(data, 256<<10, &job) != nil || job.SchemaVersion != 1 || job.Plan.Plan.Validate() != nil || job.Collection.CapturedAt.IsZero() || len(job.Collection.Collector) > 64 || job.Collection.Active && (job.Collection.DaemonStartedAt.IsZero() || job.Collection.Collector != "tetragon-json" && job.Collection.Collector != "audit-dispatcher") || len(job.Reports) < 1 || len(job.Reports) > 8 || job.Acknowledged > uint64(len(job.Reports)) {
		return nil, errors.New("state_unavailable")
	}
	for index, report := range job.Reports {
		if report.Validate() != nil || report.Sequence != uint64(index+1) || report.JobID != job.Plan.Plan.JobID || report.EnrollmentID != job.Plan.Plan.EnrollmentID || report.Revision != job.Plan.Plan.Revision {
			return nil, errors.New("state_unavailable")
		}
	}
	return &job, nil
}

func (s *Store) save(job *Job) error {
	data, err := json.Marshal(job)
	if err != nil || len(data) > 256<<10 {
		return errors.New("state_unavailable")
	}
	file, err := os.CreateTemp(s.Directory, ".job-")
	if err != nil {
		return errors.New("state_unavailable")
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("state_unavailable")
	}
	if err := os.Rename(file.Name(), filepath.Join(s.Directory, "job.json")); err != nil {
		return errors.New("state_unavailable")
	}
	return s.syncDirectory()
}
func (s *Store) syncDirectory() error {
	file, err := os.Open(s.Directory)
	if err != nil {
		return errors.New("state_unavailable")
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return errors.New("state_unavailable")
	}
	return nil
}

func (s *Store) Read() (*Job, error) {
	file, err := s.lock(".state.lock")
	if err != nil {
		return nil, err
	}
	defer unlock(file)
	return s.read()
}

// Change reloads under the journal lock, avoiding stale cross-process writes.
func (s *Store) Change(change func(*Job) (*Job, error)) error {
	file, err := s.lock(".state.lock")
	if err != nil {
		return err
	}
	defer unlock(file)
	job, err := s.read()
	if err != nil {
		return err
	}
	job, err = change(job)
	if err != nil {
		return err
	}
	if job == nil {
		return nil
	}
	return s.save(job)
}

// The caller holds the worker lock. The state lock protects another process's
// active journal write while abandoned private temporaries are removed.
func (s *Store) cleanTemporaryFiles() error {
	lock, err := s.lock(".state.lock")
	if err != nil {
		return err
	}
	defer unlock(lock)
	directory, err := os.Open(s.Directory)
	if err != nil {
		return errors.New("state_unavailable")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(257)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err != nil || len(entries) > 256 {
		return errors.New("state_unavailable")
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".download-") && !strings.HasPrefix(entry.Name(), ".job-") {
			continue
		}
		path := filepath.Join(s.Directory, entry.Name())
		if err := secureRegular(path, s.OwnerUID, true); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return errors.New("state_unavailable")
		}
	}
	return s.syncDirectory()
}
