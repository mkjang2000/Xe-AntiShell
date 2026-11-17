package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const defaultRecoveryFile = "/root/xe-antishell-offline-recovery"

type enrollmentManager interface {
	Management(context.Context, string, any, any) error
}

// runManaged verifies root before calling this helper. Input validation and
// durable local recovery preparation always precede the enrollment request.
func runEnrollCode(ctx context.Context, client enrollmentManager, args []string, stdout, stderr io.Writer) error {
	command := flag.NewFlagSet("managed enroll-code", flag.ContinueOnError)
	// The flag package reflects unknown arguments in diagnostics. An operator
	// may have pasted the secret in the wrong place, so only print safe usage.
	command.SetOutput(io.Discard)
	codeFile := command.String("code-file", "", "root-owned owner-only installation code file")
	recoveryFile := command.String("recovery-file", defaultRecoveryFile, "owner-only offline recovery file to create or reuse")
	if err := command.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			command.SetOutput(stderr)
			command.PrintDefaults()
			return flag.ErrHelp
		}
		return errors.New("invalid enroll-code arguments; use --help for usage")
	}
	if command.NArg() != 0 || *codeFile == "" || *recoveryFile == "" {
		return errors.New("enroll-code requires --code-file and an optional --recovery-file")
	}
	body, err := readBoundedFile(*codeFile, managed.MaxInstallationCodeBytes, true)
	if err != nil {
		return errors.New("cannot read the protected installation code file")
	}
	installation, err := managed.DecodeInstallationCode(string(body), time.Now())
	if err != nil {
		return err
	}
	recovery, err := prepareRecoveryFile(*recoveryFile)
	if err != nil {
		return errors.New("cannot prepare the protected offline recovery file")
	}
	input := map[string]string{
		"url": installation.CentralURL, "agent_id": installation.AgentID,
		"ca_pem": installation.CAPEM, "token": installation.Token, "recovery_code": recovery,
	}
	if err := client.Management(ctx, "enroll", input, nil); err != nil {
		// A local API or transport error may originate outside this command.
		// Do not reflect arbitrary response text next to enrollment credentials.
		return errors.New("enrollment failed; the offline recovery file was preserved for retry; check the agent status")
	}
	fmt.Fprintf(stdout, "Enrolled %s. Offline recovery code saved to %s (0600). Back it up securely off this host.\n", installation.AgentID, *recoveryFile)
	return nil
}
