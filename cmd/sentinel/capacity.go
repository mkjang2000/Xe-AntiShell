package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"xe-antishell/internal/model"
)

func writeCapacity(output io.Writer, status model.AgentStatus, jsonOutput bool) error {
	if status.CapabilityReport == nil {
		return errors.New("storage capacity measurements unavailable from this agent")
	}
	capacity, exists := status.CapabilityReport.Capability("storage.capacity")
	if !exists {
		return errors.New("storage capacity measurements unavailable from this agent")
	}
	if jsonOutput {
		return writeJSON(output, capacity)
	}
	type section struct{ title, keys string }
	sections := []section{
		{"Storage (UTC)", "utc_day measurement_started_at stored_events_today stored_bytes_today stored_events_yesterday stored_bytes_yesterday database_bytes wal_bytes disk_available_bytes oldest_event_at retention_backlog_events retention_backlog_truncated"},
		{"Ingestion (since startup)", "queue_depth queue_capacity queue_high_water last_store_latency_ms max_store_latency_ms drop_encode drop_oversize drop_queue_timeout drop_invalid drop_storage drop_shutdown"},
	}
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if capacity.State != "" {
		fmt.Fprintln(table, "Measurement status:", capacity.State)
	}
	if _, measured := capacity.Details["pending_records"]; measured {
		sections = append(sections, section{"Central delivery", "acknowledged pending_records pending_bytes spool_limit_bytes lost_records disconnect_at first_recovery_ack_at drained_at ack_recovery_seconds drain_recovery_seconds outage_lost_records"})
	} else {
		fmt.Fprintln(table, "Central delivery measurements unavailable (standalone or not yet reported).")
	}
	for _, section := range sections {
		fmt.Fprintln(table, section.title)
		for _, key := range strings.Fields(section.keys) {
			value := capacity.Details[key]
			if value == "" {
				value = "unmeasured"
			}
			fmt.Fprintf(table, "  %s\t%s\n", key, value)
		}
	}
	return table.Flush()
}
