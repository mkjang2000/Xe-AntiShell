package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"text/tabwriter"
	"time"

	"xe-antishell/internal/model"
)

type observationReader interface {
	Observations(context.Context, model.ObservationQuery) (model.ObservationReport, error)
}

func runObservations(ctx context.Context, client observationReader, args []string, stdout, stderr io.Writer, jsonOutput bool) error {
	command := flag.NewFlagSet("observations", flag.ContinueOnError)
	command.SetOutput(stderr)
	limit := command.Int("limit", 20, "number of retained observations, from 1 to 100")
	service := command.String("service", "", "exact origin service")
	protected := command.String("protected-dir", "", "absolute directory to review for this service")
	allowed := command.String("allowed-dir", "", "absolute directory excluded from candidate writes")
	if err := command.Parse(args); err != nil {
		return err
	}
	if command.NArg() != 0 {
		return fmt.Errorf("observations does not accept positional arguments: %v", command.Args())
	}
	query, err := model.ParseObservationQuery(url.Values{
		"limit": {strconv.Itoa(*limit)}, "service": {*service}, "protected_dir": {*protected}, "allowed_dir": {*allowed},
	})
	if err != nil {
		return err
	}
	report, err := client.Observations(ctx, query)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, report)
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "TIME\tSERVICE\tEVENT\tTARGET\tOUTCOME\tRETURN\tREVIEW\tEVENT ID")
	for _, sample := range report.Samples {
		target := sample.Path
		if sample.EventType == "network.connect" {
			target = sample.DestinationAddress
			if sample.DestinationPort != 0 {
				target = net.JoinHostPort(target, strconv.Itoa(int(sample.DestinationPort)))
			}
		}
		result := "-"
		if sample.ReturnValue != nil {
			result = strconv.FormatInt(*sample.ReturnValue, 10)
		}
		fmt.Fprintf(table, "%s\t%q\t%q\t%q\t%q\t%s\t%q\t%q\n",
			sample.EventTime.Local().Format(time.RFC3339Nano), sample.Service, sample.EventType, target,
			sample.Outcome, result, sample.Review, sample.EventID)
	}
	return table.Flush()
}
