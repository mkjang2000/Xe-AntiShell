package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"xe-antishell/internal/model"
)

func writeRules(w io.Writer, catalog model.RuleCatalog) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "Policy: %s (revision %d)\nCollector: %s\n", catalog.PolicySource, catalog.PolicyRevision, catalog.Collector)
	if !catalog.EvaluatedAt.IsZero() {
		fmt.Fprintln(table, "Evaluated at:", catalog.EvaluatedAt.Format(time.RFC3339Nano))
	}
	if catalog.ServiceObservationSource != "" {
		fmt.Fprintln(table, "File/TCP scopes:", catalog.ServiceObservationSource)
	}
	fmt.Fprintln(table, "ID\tVERSION\tTITLE\tPROFILE\tENABLED\tRESPONSE\tSENSORS\tREASON")
	for _, rule := range catalog.Rules {
		sensors := make([]string, 0, len(rule.Sensors))
		for _, sensor := range rule.Sensors {
			evidence := sensor.Name + "=" + sensor.State
			if sensor.VerifiedAt != nil {
				evidence += "@" + sensor.VerifiedAt.Format(time.RFC3339Nano)
			}
			sensors = append(sensors, evidence)
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%t\t%s\t%s\t%s\n", rule.ID, rule.Version, rule.Title, rule.Profile, rule.Enabled, rule.Response, strings.Join(sensors, ", "), rule.Reason)
		for _, c := range rule.ServiceControls {
			expiry := ""
			if c.ExpiresAt != nil {
				expiry = c.ExpiresAt.Format(time.RFC3339Nano)
			}
			fmt.Fprintf(table, "  %s: %s · %s · suppressed=%t · %s %s\n", c.Service, c.RuleID, c.Mode, c.Suppressed, c.Reason, expiry)
		}
	}
	return table.Flush()
}
