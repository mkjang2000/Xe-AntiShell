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
	}
	return table.Flush()
}
