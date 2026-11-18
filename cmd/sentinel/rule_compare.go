package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"xe-antishell/internal/agent"
	"xe-antishell/internal/config"
)

func runRuleComparison(ctx context.Context, args []string, stdout, stderr io.Writer, jsonOutput bool) error {
	flags := flag.NewFlagSet("rules compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	current := flags.String("current", "", "current standalone agent YAML")
	candidate := flags.String("candidate", "", "candidate standalone agent YAML")
	events := flags.String("events", "", "normalized single-host JSONL sample")
	if err := flags.Parse(args); err != nil {
		return err
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
	result, err := agent.CompareRules(ctx, before, after, f)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Sample observations: %d\n", result.Events)
	fmt.Fprintln(stdout, "RULE\tINPUT TYPE PRESENT\tCURRENT\tCANDIDATE\tADDED\tREMOVED\tCHANGED\tAFFECTED SERVICES")
	for _, r := range result.Rules {
		fmt.Fprintf(stdout, "%s\t%t\t%d\t%d\t%d\t%d\t%d\t%q\n", r.ID, r.HasInputType, r.Current, r.Candidate, r.Added, r.Removed, r.Changed, strings.Join(r.AffectedServices, ", "))
	}
	return nil
}
