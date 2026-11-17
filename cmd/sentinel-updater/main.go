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
	if os.Geteuid() != 0 || len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "sentinel-updater: fixed root service invocation required")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	bounded, stop := context.WithTimeout(ctx, 6*time.Minute)
	defer stop()
	if err := updates.NewManager().Apply(bounded); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-updater: local update journal unavailable")
		os.Exit(1)
	}
}
