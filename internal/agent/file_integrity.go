package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/buildinfo"
	"xe-antishell/internal/integrity"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func integrityPackage() (managed.RPMPackage, bool) {
	epoch, err := strconv.ParseUint(buildinfo.PackageEpoch, 10, 32)
	p := managed.RPMPackage{Name: "xe-antishell", Epoch: epoch, Version: buildinfo.PackageVersion, Release: buildinfo.PackageRelease, Arch: buildinfo.PackageArch}
	return p, err == nil && p.Validate() == nil
}

func addFileIntegrityCapability(r *model.CapabilityReport) {
	if _, ok := integrityPackage(); ok {
		r.Capabilities["integrity.agent_files"] = model.Capability{Name: "integrity.agent_files", Provider: "agent", State: model.CapabilitySupported, Implementation: "implemented", RuntimeState: "available", Reason: "bounded agent file measurement available", RuntimeReason: "an approved enrollment and policy revision start a measurement", Details: map[string]string{"contract": "1"}}
	}
}

// Requests can enable only the fixed file set for the locally applied revision.
// The on-disk signed policy is measured separately, so a changed or unreadable
// policy remains visible even while the authenticated engine is still running.
func (s *Service) currentFileAssignment(a contract.Assignment, now time.Time) bool {
	state := s.detectionState.Load()
	return state != nil && state.policy != nil && state.policy.EnrollmentID == a.EnrollmentID && state.policy.Revision == a.Revision && now.Before(state.policy.ExpiresAt) && state.policySHA256 != "" && state.policySHA256 == a.PolicySHA256
}

func (s *Service) measureRulePolicy(ctx context.Context, at time.Time) contract.Sample {
	sample := contract.Sample{MeasuredAt: at, State: "unreadable"}
	raw, oversized, err := s.store.StoredPolicyBytes(ctx)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		sample.State = "missing"
	case err != nil:
		sample.State = "unreadable"
	case oversized:
		sample.State = "too_large"
	default:
		hash := sha256.Sum256(raw)
		sample.State = "measured"
		sample.SHA256 = hex.EncodeToString(hash[:])
	}
	return sample
}

type fileMeasurementCycle struct {
	last      contract.Assignment
	completed time.Time
	pending   *contract.Report
}

type fileIntegrityClient interface {
	FileIntegrityAssignment(context.Context) (*contract.Assignment, error)
	SubmitFileIntegrity(context.Context, contract.Report) error
}

func (s *Service) measureAgentFiles(ctx context.Context, pack managed.RPMPackage, a contract.Assignment, paths map[string]string, wait func(context.Context, time.Duration) bool) *contract.Report {
	scan := integrity.NewScanner(paths)
	defer scan.Close()
	for s.currentFileAssignment(a, time.Now()) && ctx.Err() == nil {
		samples, done := scan.Step(ctx, time.Now().UTC())
		if done {
			at := time.Now().UTC()
			return &contract.Report{Assignment: a, Package: pack, Samples: samples, RulePolicy: s.measureRulePolicy(ctx, at), CompletedAt: at}
		}
		if !wait(ctx, time.Second) {
			break
		}
	}
	return nil
}

func (s *Service) checkFileIntegrity(ctx context.Context, client fileIntegrityClient, enrollment string, pack managed.RPMPackage, cycle *fileMeasurementCycle, paths map[string]string, wait func(context.Context, time.Duration) bool) {
	a, err := client.FileIntegrityAssignment(ctx)
	if err != nil {
		return
	}
	if a == nil || a.EnrollmentID != enrollment || !s.currentFileAssignment(*a, time.Now()) {
		*cycle = fileMeasurementCycle{}
		return
	}
	if *a != cycle.last || time.Since(cycle.completed) >= time.Hour {
		r := s.measureAgentFiles(ctx, pack, *a, paths, wait)
		if r == nil {
			return
		}
		*cycle = fileMeasurementCycle{last: *a, completed: r.CompletedAt, pending: r}
	}
	if cycle.pending != nil && s.currentFileAssignment(*a, time.Now()) {
		if err = client.SubmitFileIntegrity(ctx, *cycle.pending); err == nil {
			cycle.pending = nil
		}
	}
}

func (s *Service) managedFileIntegrityLoop(ctx context.Context) {
	pack, ok := integrityPackage()
	if !ok {
		return
	}
	paths := contract.Targets()
	if s.config.SourceFile != "" {
		paths[contract.ConfigID] = s.config.SourceFile
	}
	var cycle fileMeasurementCycle
	for ctx.Err() == nil {
		client, enrollment, err := s.managedConnection(ctx)
		if err == nil {
			s.checkFileIntegrity(ctx, client, enrollment.EnrollmentID, pack, &cycle, paths, managedWait)
		}
		if !managedWait(ctx, time.Minute) {
			return
		}
	}
}
