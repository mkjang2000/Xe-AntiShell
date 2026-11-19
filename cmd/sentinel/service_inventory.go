package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

type serviceInventoryClient interface {
	Capabilities(context.Context) (model.CapabilityReport, error)
}

func runServiceInventory(ctx context.Context, client serviceInventoryClient, args []string, output io.Writer, jsonOutput bool) error {
	if len(args) != 0 {
		return errors.New("service-inventory does not accept arguments")
	}
	report, err := client.Capabilities(ctx)
	if err != nil {
		return err
	}
	capability, ok := report.Capability(model.ServiceInventoryCapability)
	if !ok {
		return errors.New("the agent does not support listener inventory")
	}
	if capability.Details["contract"] != model.ServiceInventoryContract {
		return errors.New("unsupported listener inventory contract")
	}
	inventory, err := serviceInventorySnapshot(capability.Details)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(output, inventory)
	}
	return writeServiceInventory(output, inventory)
}

func serviceInventorySnapshot(details map[string]string) (model.ServiceInventory, error) {
	invalid := errors.New("invalid listener inventory report")
	var inventory model.ServiceInventory
	state := details["state"]
	switch state {
	case "pending", "complete", "partial", "unavailable", "stale":
	default:
		return inventory, invalid
	}
	if raw := details["snapshot"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &inventory); err != nil || inventory.State != state && state != "stale" {
			return inventory, invalid
		}
	}
	if len(inventory.Listeners) > model.MaxServiceInventoryListeners ||
		inventory.SampledAt.IsZero() && (len(inventory.Listeners) != 0 || state == "complete" || state == "partial" || state == "stale") {
		return inventory, invalid
	}
	for _, listener := range inventory.Listeners {
		if listener.Port == 0 || listener.Family != "ipv4" && listener.Family != "ipv6" ||
			listener.Binding != "wildcard" && listener.Binding != "loopback" && listener.Binding != "interface" ||
			listener.Service != "" && !managed.ValidApplicationService(listener.Service) {
			return inventory, invalid
		}
	}
	inventory.State = state
	if inventory.Listeners == nil {
		inventory.Listeners = []model.ServiceListener{}
	}
	return inventory, nil
}

func writeServiceInventory(output io.Writer, inventory model.ServiceInventory) error {
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "TCP listener inventory:", inventory.State)
	if !inventory.SampledAt.IsZero() {
		fmt.Fprintln(table, "Sampled at:", inventory.SampledAt.Format(time.RFC3339))
	}
	if len(inventory.Listeners) == 0 {
		if inventory.State == "complete" || inventory.State == "partial" {
			fmt.Fprintln(table, "TCP listeners in sample: 0")
		}
		return table.Flush()
	}
	fmt.Fprintln(table, "SERVICE\tPORT\tFAMILY\tBINDING")
	for _, listener := range inventory.Listeners {
		service := listener.Service
		if service == "" {
			service = "(unknown)"
		}
		fmt.Fprintf(table, "%s\t%d\t%s\t%s\n", service, listener.Port, listener.Family, listener.Binding)
	}
	return table.Flush()
}
