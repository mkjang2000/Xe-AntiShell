package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"xe-antishell/internal/buildinfo"
	"xe-antishell/internal/localapi"
	"xe-antishell/internal/model"
)

var version = buildinfo.RunningVersion()

const defaultSocketPath = "/run/xe-antishell/sentineld.sock"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	root := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	root.SetOutput(stderr)
	socket := root.String("socket", defaultSocketPath, "sentineld Unix socket")
	jsonOutput := root.Bool("json", false, "print machine-readable JSON")
	if err := root.Parse(args); err != nil {
		return err
	}
	remaining := root.Args()
	if len(remaining) == 0 {
		printUsage(stderr)
		return flag.ErrHelp
	}
	if !filepath.IsAbs(*socket) || filepath.Clean(*socket) == string(filepath.Separator) {
		return errors.New("--socket must be an absolute non-root path")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := localapi.NewClient(*socket)

	switch remaining[0] {
	case "managed":
		return runManaged(ctx, client, remaining[1:], stdout, stderr)
	case "capacity":
		if len(remaining) != 1 {
			return errors.New("capacity does not accept arguments")
		}
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		return writeCapacity(stdout, status, *jsonOutput)
	case "observations":
		return runObservations(ctx, client, remaining[1:], stdout, stderr, *jsonOutput)
	case "service-inventory":
		return runServiceInventory(ctx, client, remaining[1:], stdout, *jsonOutput)
	case "rules":
		if len(remaining) > 1 && remaining[1] == "compare" {
			return runRuleComparison(ctx, remaining[2:], stdout, stderr, *jsonOutput)
		}
		if len(remaining) != 1 {
			return errors.New("rules accepts only the compare subcommand")
		}
		catalog, err := client.Rules(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return writeJSON(stdout, catalog)
		}
		return writeRules(stdout, catalog)
	case "resources":
		if len(remaining) != 1 {
			return errors.New("resources does not accept arguments")
		}
		value, err := client.Resources(ctx)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "version":
		if len(remaining) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Fprintln(stdout, version)
		return nil
	case "status":
		if len(remaining) != 1 {
			return errors.New("status does not accept arguments")
		}
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return writeJSON(stdout, status)
		}
		fmt.Fprintf(stdout, "Version: %s\nMode: %s\nHealth: %s\nCollector: %s\nStarted: %s\nDropped: %d\nParse errors: %d\n",
			status.Version, status.Mode, status.Health, status.Collector,
			status.StartedAt.Local().Format(time.RFC3339), status.Dropped, status.ParseErrors)
		if status.LastEventAt != nil {
			fmt.Fprintf(stdout, "Last event: %s\n", status.LastEventAt.Local().Format(time.RFC3339Nano))
		}
		writeCollectorGap(stdout, status)
		if status.LastError != "" {
			fmt.Fprintf(stdout, "Last error: %q\n", status.LastError)
		}
		return nil
	case "capabilities":
		refresh := flag.NewFlagSet("capabilities", flag.ContinueOnError)
		refresh.SetOutput(stderr)
		force := refresh.Bool("refresh", false, "run the host probe again")
		if err := refresh.Parse(remaining[1:]); err != nil {
			return err
		}
		if refresh.NArg() != 0 {
			return fmt.Errorf("capabilities does not accept positional arguments: %v", refresh.Args())
		}
		var value model.CapabilityReport
		var err error
		if *force {
			value, err = client.RefreshCapabilities(ctx)
		} else {
			value, err = client.Capabilities(ctx)
		}
		if err != nil {
			return err
		}
		if *jsonOutput {
			return writeJSON(stdout, value)
		}
		fmt.Fprintf(stdout, "Platform: %s (%s)\nKernel: %s\nBoot ID: %s\nProbed: %s\n",
			value.Platform.PrettyName, value.Platform.Architecture,
			value.Platform.KernelRelease, value.Platform.BootID, value.ProbedAt.Local().Format(time.RFC3339))
		names := make([]string, 0, len(value.Capabilities))
		for name := range value.Capabilities {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			capability := value.Capabilities[name]
			fmt.Fprintf(stdout, "%-24s %-12s %s\n", name, capability.State, capability.Reason)
		}
		return nil
	case "events":
		limit, err := parseLimit("events", remaining[1:], stderr)
		if err != nil {
			return err
		}
		value, err := client.Events(ctx, limit)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "findings":
		limit, err := parseLimit("findings", remaining[1:], stderr)
		if err != nil {
			return err
		}
		value, err := client.Findings(ctx, limit)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "process-tree":
		command := flag.NewFlagSet("process-tree", flag.ContinueOnError)
		command.SetOutput(stderr)
		pid := command.Int("pid", 0, "process ID")
		if err := command.Parse(remaining[1:]); err != nil {
			return err
		}
		if command.NArg() != 0 {
			return fmt.Errorf("process-tree does not accept positional arguments: %v", command.Args())
		}
		if *pid < 1 {
			return fmt.Errorf("process-tree requires --pid with a positive value")
		}
		value, err := client.ProcessTree(ctx, *pid)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "audit-plugin":
		command := flag.NewFlagSet("audit-plugin", flag.ContinueOnError)
		command.SetOutput(stderr)
		maxLine := command.Int("max-line-bytes", 1<<20, "maximum audit dispatcher record size")
		if err := command.Parse(remaining[1:]); err != nil {
			return err
		}
		if command.NArg() != 0 {
			return fmt.Errorf("audit-plugin does not accept positional arguments: %v", command.Args())
		}
		if *maxLine < 1 || *maxLine > 64<<20 {
			return errors.New("--max-line-bytes must be between 1 and 67108864")
		}
		return client.StreamAudit(ctx, os.Stdin, *maxLine)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", remaining[0])
	}
}

func writeCollectorGap(output io.Writer, status model.AgentStatus) {
	if status.Collector != "tetragon-json" || status.CapabilityReport == nil {
		return
	}
	details := status.CapabilityReport.Capabilities["collector.tetragon"].Details
	start, err := time.Parse(time.RFC3339Nano, details["last_disconnect_at"])
	if err != nil {
		return
	}
	end := "pending"
	if recovered := details["last_recovered_at"]; recovered != "" {
		if at, err := time.Parse(time.RFC3339Nano, recovered); err == nil {
			end = at.Local().Format(time.RFC3339Nano)
		} else {
			end = "unknown"
		}
	}
	fmt.Fprintf(output, "Last collection interruption: %s\nCollection recovery: %s\n", start.Local().Format(time.RFC3339Nano), end)
	if attempts, err := strconv.ParseUint(details["reconnect_attempts"], 10, 64); err == nil {
		fmt.Fprintf(output, "Reconnect attempts since startup: %d\n", attempts)
	}
}

func parseLimit(name string, args []string, output io.Writer) (int, error) {
	command := flag.NewFlagSet(name, flag.ContinueOnError)
	command.SetOutput(output)
	limit := command.Int("limit", 100, "maximum results")
	if err := command.Parse(args); err != nil {
		return 0, err
	}
	if command.NArg() != 0 {
		return 0, fmt.Errorf("%s does not accept positional arguments: %v", name, command.Args())
	}
	if *limit < 1 || *limit > 100000 {
		return 0, fmt.Errorf("limit must be between 1 and %s", strconv.Itoa(100000))
	}
	return *limit, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	return encoder.Encode(value)
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, `Usage: sentinel [--socket PATH] [--json] COMMAND

Commands:
  status
  capabilities [--refresh]
  events [--limit N]
  findings [--limit N]
  rules [compare --help]
  observations [--limit N] [--service UNIT] [--protected-dir ABS] [--allowed-dir ABS]
  service-inventory
  resources
  capacity
  managed status|enroll|challenge|authorize-removal|recover-removal|removal-check
  process-tree --pid PID
  audit-plugin [--max-line-bytes N]
  version`)
}
