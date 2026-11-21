package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xe-antishell/internal/updates"
)

func main() {
	removal := len(os.Args) == 2 && os.Args[1] == "--remote-removal"
	if os.Geteuid() != 0 || len(os.Args) != 1 && !removal {
		fmt.Fprintln(os.Stderr, "sentinel-updater: fixed root service invocation required")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	bounded, stop := context.WithTimeout(ctx, 6*time.Minute)
	defer stop()
	manager := updates.NewManager()
	if removal {
		if err := manager.ApplyRemoteRemoval(bounded); err != nil {
			fmt.Fprintln(os.Stderr, "sentinel-updater: remote removal work remains in the local journal")
			os.Exit(1)
		}
		return
	}
	if err := manager.Apply(bounded); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-updater: local update journal unavailable")
		os.Exit(1)
	}
}
