package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
)

type fileCycleClient struct {
	assignment *contract.Assignment
	reports    []contract.Report
	fail       bool
}

func (c *fileCycleClient) FileIntegrityAssignment(context.Context) (*contract.Assignment, error) {
	return c.assignment, nil
}

func (c *fileCycleClient) SubmitFileIntegrity(ctx context.Context, r contract.Report) error {
	c.reports = append(c.reports, r)
	if c.fail {
		return errors.New("disconnected")
	}
	return nil
}

func TestFileCyclePolicyBindingRetryAndRecheck(t *testing.T) {
	s, db := newTestService(t, config.CollectorDisabled, nil)
	defer db.Close()
	ctx := context.Background()
	enrollment, p, key := managedPolicyFixture(t)
	signed := signRuntimePolicy(t, p, key)
	if err := s.applyManagedPolicy(ctx, signed, enrollment, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	sum, err := contract.PolicyDigest(signed)
	if err != nil {
		t.Fatal(err)
	}
	a := contract.Assignment{EnrollmentID: enrollment.EnrollmentID, Revision: p.Revision, PolicySHA256: sum}
	pack := managed.RPMPackage{Name: "xe-antishell", Version: "1", Release: "1.el9", Arch: "x86_64"}
	c := &fileCycleClient{assignment: &a, fail: true}
	paths := contract.Targets()
	dir := t.TempDir()
	for id := range paths {
		paths[id] = filepath.Join(dir, id)
		if err := os.WriteFile(paths[id], []byte(id), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var cycle fileMeasurementCycle
	run := func() {
		s.checkFileIntegrity(ctx, c, enrollment.EnrollmentID, pack, &cycle, paths, func(context.Context, time.Duration) bool { return true })
	}
	a.Revision++
	run()
	if len(c.reports) != 0 {
		t.Fatal("scanned on unapproved revision")
	}
	a.Revision--
	a.PolicySHA256 = strings.Repeat("0", 64)
	run()
	if len(c.reports) != 0 {
		t.Fatal("scanned on different signed policy digest")
	}
	a.PolicySHA256 = sum
	run()
	if len(c.reports) != 1 || !c.reports[0].Valid(time.Now()) || c.reports[0].RulePolicy.SHA256 != sum {
		t.Fatalf("missing or invalid complete report: %v", c.reports)
	}
	if err = os.Remove(paths[contract.ConfigID]); err != nil {
		t.Fatal(err)
	}
	c.fail = false
	run()
	run()
	if len(c.reports) != 2 || c.reports[0].CompletedAt != c.reports[1].CompletedAt || c.reports[1].Samples[contract.ConfigID].State != "measured" {
		t.Fatal("failed delivery remeasured or successful delivery repeated")
	}
	cycle.completed = cycle.completed.Add(-time.Hour)
	run()
	if c.reports[2].Samples[contract.ConfigID].State != "missing" {
		t.Fatal("new scan failed to find missing file")
	}
	c.assignment = nil
	run()
	if cycle.last.Revision != 0 {
		t.Fatal("disabled assignment retained")
	}
}
