package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/agent"
	"xe-antishell/internal/config"
)

func readImpactFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("policy comparison input exceeds its limit")
	}
	return b, nil
}

func compareManagedInput(ctx context.Context, inputPath, hostPath, eventPath string, out io.Writer) error {
	inputJSON, err := readImpactFile(inputPath, 3*managed.MaxPolicyBytes)
	if err != nil {
		return err
	}
	var input managed.PolicyImpactInput
	if err = managed.DecodeStrict(inputJSON, 3*managed.MaxPolicyBytes, &input); err != nil {
		return err
	}
	id, err := input.Digest()
	if err != nil {
		return err
	}
	hostBytes, err := readImpactFile(hostPath, 4<<20)
	if err != nil {
		return err
	}
	host, err := config.Decode(bytes.NewReader(hostBytes))
	if err != nil {
		return err
	}
	current := host.WithManagedDetection(input.Current.Detection)
	candidate := host.WithManagedDetection(input.Candidate.Detection)
	f, err := os.Open(eventPath)
	if err != nil {
		return err
	}
	defer f.Close()
	sample := sha256.New()
	compared, err := agent.CompareRulesAt(ctx, current, candidate, io.TeeReader(f, sample), input.EvaluatedAt)
	if err != nil {
		return err
	}
	h := sha256.Sum256(hostBytes)
	report := managed.PolicyImpactReport{InputDigest: id, SampleDigest: hex.EncodeToString(sample.Sum(nil)), HostDigest: hex.EncodeToString(h[:]), EvaluatedAt: compared.EvaluatedAt, Events: compared.Events}
	for _, r := range compared.Rules {
		report.Rules = append(report.Rules, managed.PolicyRuleImpact{ID: r.ID, HasInput: r.HasInputType, Current: r.Current, Candidate: r.Candidate, Added: r.Added, Removed: r.Removed, Changed: r.Changed})
	}
	if err = report.ValidateFor(input); err != nil {
		return err
	}
	return writeJSON(out, report)
}
