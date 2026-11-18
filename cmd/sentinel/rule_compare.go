package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"xe-antishell/internal/agent"
	"xe-antishell/internal/config"
)

func runRuleComparison(ctx context.Context, args []string, stdout, stderr io.Writer, jsonOutput bool) error {
	flags := flag.NewFlagSet("rules compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	current := flags.String("current", "", "current standalone agent YAML")
	candidate := flags.String("candidate", "", "candidate standalone agent YAML")
	events := flags.String("events", "", "normalized single-host JSONL sample")
	at := flags.String("at", "", "fixed RFC3339 evaluation time for both policies (default: now)")
	impact := flags.String("managed-input", "", "policy impact input exported by Central")
	host := flags.String("host-config", "", "effective agent host YAML used for replay")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *impact != "" || *host != "" {
		if flags.NArg() != 0 || *impact == "" || *host == "" || *events == "" || *current != "" || *candidate != "" || *at != "" {
			return errors.New("managed comparison requires --managed-input, --host-config and --events")
		}
		return compareManagedInput(ctx, *impact, *host, *events, stdout)
	}
	if flags.NArg() != 0 || *current == "" || *candidate == "" || *events == "" {
		return errors.New("rules compare requires --current, --candidate and --events")
	}
	before, err := config.Load(*current)
	if err != nil {
		return fmt.Errorf("current configuration: %w", err)
	}
	after, err := config.Load(*candidate)
	if err != nil {
		return fmt.Errorf("candidate configuration: %w", err)
	}
	f, err := os.Open(*events)
	if err != nil {
		return err
	}
	defer f.Close()
	evaluationTime := time.Now()
	if *at != "" {
		evaluationTime, err = time.Parse(time.RFC3339Nano, *at)
		if err != nil {
			return errors.New("--at requires an RFC3339 timestamp")
		}
	}
	result, err := agent.CompareRulesAt(ctx, before, after, f, evaluationTime)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Sample observations: %d\nEvaluation time: %s\n", result.Events, result.EvaluatedAt.Format(time.RFC3339Nano))
	fmt.Fprintln(stdout, "RULE\tINPUT TYPE PRESENT\tCURRENT\tCANDIDATE\tADDED\tREMOVED\tCHANGED\tAFFECTED SERVICES")
	for _, r := range result.Rules {
		fmt.Fprintf(stdout, "%s\t%t\t%d\t%d\t%d\t%d\t%d\t%q\n", r.ID, r.HasInputType, r.Current, r.Candidate, r.Added, r.Removed, r.Changed, strings.Join(r.AffectedServices, ", "))
	}
	return nil
}
