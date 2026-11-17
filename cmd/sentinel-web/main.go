package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"xe-antishell/internal/localapi"
	"xe-antishell/internal/webpanel"
)

const version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-web:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return flag.ErrHelp
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Fprintln(stdout, version)
		return nil
	case "init-auth":
		return initAuth(args[1:], stdout, stderr)
	case "serve":
		return serve(args[1:], stderr)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func initAuth(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init-auth", flag.ContinueOnError)
	flags.SetOutput(stderr)
	authPath := flags.String("file", "/etc/xe-antishell/web-auth.json", "auth file to create")
	passwordPath := flags.String("initial-password-file", "/root/xe-antishell-web-initial-password.txt", "root-only initial password file")
	username := flags.String("username", "admin", "administrator username")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("init-auth does not accept positional arguments: %v", flags.Args())
	}
	password, err := webpanel.GeneratePassword()
	if err != nil {
		return err
	}
	credentials, err := webpanel.GenerateCredentials(*username, password, webpanel.DefaultArgon2Parameters())
	if err != nil {
		return err
	}
	if err := webpanel.WriteCredentials(*authPath, credentials); err != nil {
		return err
	}
	if err := webpanel.WriteInitialPassword(*passwordPath, password); err != nil {
		if removeErr := os.Remove(*authPath); removeErr != nil {
			return errors.Join(err, fmt.Errorf("remove incomplete auth file: %w", removeErr))
		}
		return err
	}
	fmt.Fprintf(stdout, "Web administrator created.\nUsername: %s\nAuth file: %s\nInitial password file: %s\nDelete the initial password file after first login.\n", *username, *authPath, *passwordPath)
	return nil
}

func serve(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", "127.0.0.1:9088", "literal IP listen address")
	allowNonLoopback := flags.Bool("allow-non-loopback", false, "allow binding to a non-loopback literal IP")
	socketPath := flags.String("socket", "/run/xe-antishell/sentineld.sock", "sentineld Unix socket")
	authPath := flags.String("auth-file", "/etc/xe-antishell/web-auth.json", "web authentication file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("serve does not accept positional arguments: %v", flags.Args())
	}
	if !filepath.IsAbs(*socketPath) || filepath.Clean(*socketPath) == string(filepath.Separator) {
		return errors.New("--socket must be an absolute non-root path")
	}
	if !filepath.IsAbs(*authPath) {
		return errors.New("--auth-file must be an absolute path")
	}
	credentials, err := webpanel.LoadCredentials(*authPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	panel, err := webpanel.NewServer(credentials, localapi.NewClient(*socketPath), logger)
	if err != nil {
		return err
	}
	server, listener, err := panel.HTTPServer(*listenAddress, *allowNonLoopback)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverError := make(chan error, 1)
	go func() { serverError <- server.Serve(listener) }()
	logger.Info("sentinel web panel started", "listen", listener.Addr().String(), "socket", *socketPath)
	select {
	case <-ctx.Done():
	case err := <-serverError:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve web panel: %w", err)
		}
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, `Usage: sentinel-web COMMAND [OPTIONS]

Commands:
  serve       Start the monitoring panel
  init-auth   Create administrator credentials and an initial password file
  version`)
}
