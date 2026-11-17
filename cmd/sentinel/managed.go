package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"

	"xe-antishell/internal/localapi"
	"xe-antishell/internal/managed"
)

func readBoundedFile(path string, maximum int, secret bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(maximum) {
		return nil, errors.New("input must be a bounded regular file")
	}
	if secret && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret input file must have owner-only permissions")
	}
	if secret {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return nil, err
		}
		if stat.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("secret input file must be owned by the caller")
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if len(data) > maximum {
		return nil, errors.New("input file exceeds its size limit")
	}
	return data, err
}

func runManaged(ctx context.Context, client *localapi.Client, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("managed requires a subcommand")
	}
	if args[0] == "status" {
		if len(args) != 1 {
			return errors.New("managed status does not accept arguments")
		}
		value, err := client.ManagedStatus(ctx)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	}
	if os.Geteuid() != 0 {
		return errors.New("managed changes require root")
	}
	command := flag.NewFlagSet("managed "+args[0], flag.ContinueOnError)
	command.SetOutput(stderr)
	var input any = struct{}{}
	action := args[0]
	switch action {
	case "enroll":
		central := command.String("central", "", "HTTPS central URL")
		agentID := command.String("agent-id", "", "unique agent ID")
		caFile := command.String("ca-file", "", "pinned central CA file")
		tokenFile := command.String("token-file", "", "owner-only enrollment token file")
		recoveryFile := command.String("recovery-file", "", "new owner-only offline recovery code file")
		if err := command.Parse(args[1:]); err != nil {
			return err
		}
		if command.NArg() != 0 || *central == "" || *agentID == "" || *caFile == "" || *tokenFile == "" || *recoveryFile == "" {
			return errors.New("enroll requires --central --agent-id --ca-file --token-file --recovery-file")
		}
		ca, err := readBoundedFile(*caFile, 64<<10, false)
		if err != nil {
			return err
		}
		token, err := readBoundedFile(*tokenFile, 4096, true)
		if err != nil {
			return err
		}
		code, err := prepareRecoveryFile(*recoveryFile)
		if err != nil {
			return err
		}
		input = map[string]string{"url": *central, "agent_id": *agentID, "ca_pem": string(ca), "token": strings.TrimSpace(string(token)), "recovery_code": code}
		if err := client.Management(ctx, "enroll", input, nil); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Enrolled %s. Offline recovery code saved to %s (0600).\n", *agentID, *recoveryFile)
		return nil
	case "challenge", "removal-check":
		if err := command.Parse(args[1:]); err != nil {
			return err
		}
		if command.NArg() != 0 {
			return errors.New("unexpected management arguments")
		}
	case "authorize-removal", "recover-removal":
		operation := command.String("operation", "", "prepared removal operation ID")
		file := command.String("grant-file", "", "owner-only signed central grant file")
		recovery := command.String("code-file", "", "owner-only offline recovery file")
		if err := command.Parse(args[1:]); err != nil {
			return err
		}
		if command.NArg() != 0 || *operation == "" {
			return errors.New("removal authorization requires --operation")
		}
		if action == "authorize-removal" {
			if *file == "" || *recovery != "" {
				return errors.New("authorize-removal requires only --grant-file")
			}
			body, err := readBoundedFile(*file, 32<<10, true)
			if err != nil {
				return err
			}
			var grant managed.SignedRemovalGrant
			if err := managed.DecodeStrict(body, 32<<10, &grant); err != nil {
				return err
			}
			input = map[string]any{"operation_id": *operation, "grant": grant}
		} else {
			if *recovery == "" || *file != "" {
				return errors.New("recover-removal requires only --code-file")
			}
			body, err := readBoundedFile(*recovery, 4096, true)
			if err != nil {
				return err
			}
			input = map[string]string{"operation_id": *operation, "recovery": strings.TrimSpace(string(body))}
		}
		action = "authorize"
	default:
		return errors.New("unknown managed command")
	}
	var output json.RawMessage
	if err := client.Management(ctx, action, input, &output); err != nil {
		return err
	}
	return writeJSON(stdout, output)
}

// Save before enrollment so a lost local API response cannot lose the only
// recovery credential. Retrying uses the same protected file.
func prepareRecoveryFile(path string) (string, error) {
	if _, err := os.Lstat(path); err == nil {
		body, err := readBoundedFile(path, 128, true)
		if err != nil {
			return "", err
		}
		code := strings.TrimSpace(string(body))
		raw, err := base64.RawURLEncoding.DecodeString(code)
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != code {
			return "", errors.New("recovery file does not contain a valid code")
		}
		return code, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(raw)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := io.WriteString(file, code+"\n"); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return "", err
	}
	return code, nil
}
