// Package privileges reconciles one compiled, monitor-only credential policy.
// It accepts no remote YAML, command, address or policy name.
package privileges

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"xe-antishell/internal/model"
)

//go:embed credential-policy.yaml
var policy []byte

const PolicyName = model.CredentialPolicyName
const markerName = "owner.json"

type Status struct {
	Supported    bool
	Loaded       bool
	GenerationAt time.Time
	Error        string
}
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type Controller struct {
	Command, Socket, Directory string
	Runner                     Runner
	mu                         sync.RWMutex
	status                     Status
	operation                  sync.Mutex
	socketKey                  string
	checkCommand               func(string) error
	checkSocket                func(string) error
	checkParent                func(string) error
}
type ownership struct {
	Policy string `json:"policy"`
	SHA256 string `json:"sha256"`
}
type policyState struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Domain    string `json:"domain"`
	State     string `json:"state"`
	Mode      string `json:"mode"`
	Error     string `json:"error"`
	Hooks     []struct {
		State string `json:"state"`
	} `json:"hook_statuses"`
}

func New(command string, args []string, directory string) *Controller {
	socket := ""
	for i, arg := range args {
		if arg == "--server-address" && i+1 < len(args) {
			socket = args[i+1]
		}
		if strings.HasPrefix(arg, "--server-address=") {
			socket = strings.TrimPrefix(arg, "--server-address=")
		}
	}
	c := &Controller{Command: command, Socket: socket, Directory: directory, Runner: ExecRunner{}, checkCommand: trustedExecutable, checkSocket: trustedSocket, checkParent: trustedAncestors}
	c.status.Supported = os.Geteuid() == 0 && filepath.IsAbs(command) && strings.HasPrefix(socket, "unix:///run/") && filepath.IsAbs(directory)
	if c.status.Supported && trustedExecutable(command) != nil {
		c.status.Supported = false
	}
	return c
}
func (c *Controller) Snapshot() Status { c.mu.RLock(); defer c.mu.RUnlock(); return c.status }
func (c *Controller) update(loaded bool, generation time.Time, code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.Loaded && !loaded {
		generation = time.Now().UTC()
	}
	c.status.Loaded = loaded
	c.status.Error = code
	if !generation.IsZero() {
		c.status.GenerationAt = generation
	}
}
func (c *Controller) Reconcile(ctx context.Context, enabled bool) {
	c.operation.Lock()
	defer c.operation.Unlock()
	current := c.Snapshot()
	if !current.Supported {
		if enabled {
			c.update(false, time.Time{}, "controller_unavailable")
		}
		return
	}
	owner, exists, err := c.readOwner()
	if err != nil {
		c.update(false, time.Time{}, "ownership_invalid")
		return
	}
	if !enabled && !exists {
		c.update(false, time.Time{}, "")
		return
	}
	if c.checkCommand(c.Command) != nil || c.checkSocket(c.Socket) != nil {
		c.update(false, time.Time{}, "control_endpoint_unavailable")
		return
	}
	if key := socketIdentity(c.Socket); key != "" && key != c.socketKey {
		c.socketKey = key
		c.update(false, time.Now().UTC(), "")
		current = c.Snapshot()
	}
	entries, err := c.list(ctx)
	if err != nil {
		c.update(false, time.Time{}, "policy_list_failed")
		return
	}
	var found *policyState
	for i := range entries {
		if entries[i].Name == PolicyName {
			if found != nil {
				c.update(false, time.Time{}, "ambiguous_policy")
				return
			}
			found = &entries[i]
		}
	}
	digest := sha256.Sum256(policy)
	expected := ownership{Policy: PolicyName, SHA256: hex.EncodeToString(digest[:])}
	if exists && owner != expected {
		c.update(false, time.Time{}, "ownership_version_mismatch")
		return
	}
	if found != nil && (!exists || found.Domain != "static" || found.Namespace != "") {
		c.update(false, time.Time{}, "foreign_policy")
		return
	}
	if !enabled {
		if found != nil {
			if _, err := c.call(ctx, "delete", PolicyName, "--domain", "static"); err != nil {
				c.update(false, time.Time{}, "policy_delete_failed")
				return
			}
		}
		if err := os.Remove(filepath.Join(c.Directory, markerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.update(false, time.Time{}, "ownership_remove_failed")
			return
		}
		_ = os.Remove(filepath.Join(c.Directory, "policy.yaml"))
		c.update(false, time.Time{}, "")
		return
	}
	generation := current.GenerationAt
	if found == nil {
		generation = time.Now().UTC()
		c.update(false, generation, "")
		if err := c.ensurePrivateDirectory(); err != nil {
			c.update(false, generation, "private_state_unavailable")
			return
		}
		if err := privateWrite(filepath.Join(c.Directory, "policy.yaml"), policy); err != nil {
			c.update(false, generation, "policy_stage_failed")
			return
		}
		raw, _ := json.Marshal(expected)
		// Durable intent precedes load, so a crash after add can reconcile ownership.
		if err := privateWrite(filepath.Join(c.Directory, markerName), raw); err != nil {
			c.update(false, generation, "ownership_save_failed")
			return
		}
		if _, err := c.call(ctx, "add", filepath.Join(c.Directory, "policy.yaml"), "--domain", "static"); err != nil {
			c.update(false, generation, "policy_add_failed")
			return
		}
		entries, err = c.list(ctx)
		if err != nil {
			c.update(false, generation, "policy_list_failed")
			return
		}
		for i := range entries {
			if entries[i].Name == PolicyName {
				found = &entries[i]
				break
			}
		}
	}
	if found == nil || !ready(*found) {
		c.update(false, generation, "policy_not_ready")
		return
	}
	if generation.IsZero() || !current.Loaded {
		// An unknown/not-ready interval invalidates the old receipt epoch, even
		// if this socket and policy name are unchanged when control recovers.
		generation = time.Now().UTC()
	}
	c.update(true, generation, "")
}
func ready(p policyState) bool {
	if p.Domain != "static" || p.Namespace != "" || p.State != "TP_STATE_ENABLED" || p.Mode != "TP_MODE_MONITOR_ONLY" || p.Error != "" || len(p.Hooks) == 0 {
		return false
	}
	for _, h := range p.Hooks {
		if h.State != "STATUS_LOADED" {
			return false
		}
	}
	return true
}
func (c *Controller) call(ctx context.Context, action string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := []string{"--server-address", c.Socket, "tracingpolicy", action}
	command = append(command, args...)
	return c.Runner.Run(bounded, c.Command, command...)
}
func (c *Controller) list(ctx context.Context) ([]policyState, error) {
	data, err := c.call(ctx, "list", "-o", "json")
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("policy list unavailable")
	}
	return decodePolicyList(data)
}
func (c *Controller) readOwner() (ownership, bool, error) {
	p := filepath.Join(c.Directory, markerName)
	var o ownership
	if _, err := os.Lstat(c.Directory); errors.Is(err, os.ErrNotExist) {
		return o, false, nil
	} else if err != nil {
		return o, false, err
	}
	if err := privateDirectory(c.Directory); err != nil {
		return o, false, err
	}
	if err := privateFile(p); errors.Is(err, os.ErrNotExist) {
		return o, false, nil
	} else if err != nil {
		return o, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 2048 {
		return o, false, errors.New("invalid owner")
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return o, false, err
	}
	return o, true, nil
}
func trustedExecutable(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(real) {
		return errors.New("untrusted executable")
	}
	if err := trustedAncestors(filepath.Dir(real)); err != nil {
		return err
	}
	s, err := os.Lstat(real)
	if err != nil {
		return err
	}
	owner, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || s.Mode().Perm()&022 != 0 || s.Mode().Perm()&0111 == 0 || owner.Uid != 0 {
		return errors.New("untrusted executable")
	}
	return nil
}
func trustedSocket(address string) error {
	p := strings.TrimPrefix(address, "unix://")
	if !strings.HasPrefix(address, "unix:///run/") || filepath.Clean(p) != p {
		return errors.New("invalid socket")
	}
	if err := trustedAncestors(filepath.Dir(p)); err != nil {
		return err
	}
	s, err := os.Lstat(p)
	if err != nil {
		return err
	}
	o, ok := s.Sys().(*syscall.Stat_t)
	if !ok || s.Mode()&os.ModeSocket == 0 || o.Uid != 0 || s.Mode().Perm()&0002 != 0 || (s.Mode().Perm()&0020 != 0 && o.Gid != 0) {
		return errors.New("untrusted socket")
	}
	return nil
}
func trustedAncestors(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		s, err := os.Lstat(p)
		if err != nil {
			return err
		}
		o, ok := s.Sys().(*syscall.Stat_t)
		if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || o.Uid != 0 || s.Mode().Perm()&022 != 0 {
			return errors.New("untrusted directory")
		}
		if p == "/" {
			return nil
		}
	}
}
func privateDirectory(p string) error {
	s, err := os.Lstat(p)
	if err != nil {
		return err
	}
	o, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.IsDir() || s.Mode().Perm() != 0700 || o.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid private directory")
	}
	return nil
}
func (c *Controller) ensurePrivateDirectory() error {
	p := c.Directory
	if err := c.checkParent(filepath.Dir(p)); err != nil {
		return err
	}
	if err := os.Mkdir(p, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return privateDirectory(p)
}
func privateFile(p string) error {
	s, err := os.Lstat(p)
	if err != nil {
		return err
	}
	o, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || o.Uid != uint32(os.Geteuid()) || o.Nlink != 1 {
		return errors.New("invalid private file")
	}
	return nil
}
func privateWrite(p string, b []byte) error {
	if err := privateFile(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".privilege-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, p); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func socketIdentity(address string) string {
	s, err := os.Lstat(strings.TrimPrefix(address, "unix://"))
	if err != nil {
		return ""
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d", st.Dev, st.Ino, st.Ctim.Sec, st.Ctim.Nsec)
}
