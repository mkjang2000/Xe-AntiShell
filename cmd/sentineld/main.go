package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"xe-antishell/internal/agent"
	"xe-antishell/internal/config"
	"xe-antishell/internal/localapi"
	"xe-antishell/internal/storage"
)

const defaultConfigPath = "/etc/xe-antishell/sentineld.yaml"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("sentineld stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("sentineld", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath, "configuration file")
	dataDir := flags.String("data-dir", "", "override data directory")
	socketPath := flags.String("socket", "", "override local API Unix socket")
	collectorMode := flags.String("collector", "", "override collector: auto, tetragon, audit, replay, disabled")
	replayPath := flags.String("replay", "", "absolute replay JSONL path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	visited := make(map[string]bool)
	flags.Visit(func(value *flag.Flag) { visited[value.Name] = true })
	if visited["collector"] && visited["replay"] && *collectorMode != string(config.CollectorReplay) {
		return errors.New("--replay can only be combined with --collector=replay")
	}

	allowMissingConfig := !visited["config"] || *configPath == defaultConfigPath
	cfg, err := loadConfig(*configPath, allowMissingConfig)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		if !filepath.IsAbs(*dataDir) || filepath.Clean(*dataDir) == string(filepath.Separator) {
			return errors.New("--data-dir must be an absolute non-root path")
		}
		cfg.Agent.DatabasePath = filepath.Join(filepath.Clean(*dataDir), "sentineld.db")
	}
	if *socketPath != "" {
		cfg.Agent.SocketPath = *socketPath
	}
	if *collectorMode != "" {
		cfg.Collector.Mode = config.CollectorMode(*collectorMode)
	}
	if *replayPath != "" {
		cfg.Collector.Mode = config.CollectorReplay
		cfg.Collector.Replay.Path = *replayPath
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate effective configuration: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Agent.DatabasePath), 0o750); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := storage.Open(ctx, cfg.Agent.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	service, err := agent.New(cfg, store, nil)
	if err != nil {
		return err
	}
	if err := service.Start(ctx); err != nil {
		return err
	}
	serviceStopped := false
	defer func() {
		if serviceStopped {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = service.Shutdown(shutdownCtx)
	}()

	listener, err := localapi.ListenUnix(cfg.Agent.SocketPath, 0o660)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := localapi.NewServer(service, cfg.Limits.QueryDefault, cfg.Limits.QueryMaximum, cfg.Limits.MaxEventBytes)
	serverError := make(chan error, 1)
	go func() { serverError <- server.Serve(listener) }()

	slog.Info("sentineld started",
		"version", agent.Version,
		"socket", cfg.Agent.SocketPath,
		"database", cfg.Agent.DatabasePath,
		"collector_mode", cfg.Collector.Mode,
	)
	var serveErr error
	select {
	case <-ctx.Done():
	case err := <-serverError:
		if err != nil {
			serveErr = fmt.Errorf("serve local API: %w", err)
		}
	}

	serverShutdownCtx, cancelServer := context.WithTimeout(context.Background(), 5*time.Second)
	serverShutdownErr := server.Shutdown(serverShutdownCtx)
	cancelServer()
	if serverShutdownErr != nil {
		serverShutdownErr = fmt.Errorf("shutdown local API: %w", serverShutdownErr)
	}

	serviceShutdownCtx, cancelService := context.WithTimeout(context.Background(), 5*time.Second)
	serviceShutdownErr := service.Shutdown(serviceShutdownCtx)
	cancelService()
	if serviceShutdownErr != nil {
		serviceShutdownErr = fmt.Errorf("shutdown agent service: %w", serviceShutdownErr)
	} else {
		serviceStopped = true
	}
	return errors.Join(serveErr, serverShutdownErr, serviceShutdownErr)
}

func loadConfig(path string, allowMissing bool) (config.Config, error) {
	cfg, err := config.Load(path)
	if err == nil {
		return cfg, nil
	}
	if allowMissing && errors.Is(err, os.ErrNotExist) {
		return config.Default(), nil
	}
	return config.Config{}, err
}
