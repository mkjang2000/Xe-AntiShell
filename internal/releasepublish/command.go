package releasepublish

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const usage = "Usage: xeas-release keygen|public|prepare|sign|verify [options]\nPrivate signing keys stay on the build host and are never sent to central.\n"

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "cannot determine signing directory")
		return 1
	}
	directory := filepath.Join(home, ".local", "share", "xe-antishell-release")
	options := flag.NewFlagSet("xeas-release", flag.ContinueOnError)
	options.SetOutput(io.Discard)
	key := options.String("key", filepath.Join(directory, "publisher-key.pem"), "private PKCS8 key file")
	dir := options.String("dir", directory, "private key directory")
	rpm := options.String("rpm", "", "agent RPM")
	manifest := options.String("manifest", "", "release manifest JSON")
	out := options.String("out", "", "new public output file")
	if options.Parse(args[1:]) != nil || options.NArg() != 0 {
		fmt.Fprintln(stderr, "invalid release command options")
		return 2
	}
	var result any
	switch args[0] {
	case "keygen":
		result, err = GenerateKey(*dir)
	case "public":
		var private ed25519.PrivateKey
		private, err = ReadPrivateKey(*key)
		if err == nil {
			result = Public(private)
			clear(private)
		}
	case "prepare":
		if *rpm == "" || *out == "" {
			err = errors.New("prepare requires --rpm and --out")
			break
		}
		var value managed.ReleaseManifest
		value, err = Prepare(context.Background(), *rpm, time.Now())
		if err == nil {
			err = WriteJSON(*out, value, 0o644)
		}
		result = map[string]string{"manifest": *out}
	case "sign":
		if *rpm == "" || *manifest == "" || *out == "" {
			err = errors.New("sign requires --rpm, --manifest and --out")
			break
		}
		var value managed.ReleaseManifest
		if err = ReadJSON(*manifest, &value); err == nil {
			err = CheckArtifact(value, *rpm)
		}
		if err == nil {
			var pack managed.RPMPackage
			var major string
			pack, major, err = InspectRPM(context.Background(), *rpm)
			if err == nil && (pack != value.Package || major != value.OSMajor) {
				err = errors.New("RPM header does not match release metadata")
			}
		}
		var private ed25519.PrivateKey
		if err == nil {
			private, err = ReadPrivateKey(*key)
		}
		if err == nil {
			public := Public(private)
			var signed managed.SignedReleaseManifest
			signed, err = managed.SignReleaseManifest(value, public.KeyID, private)
			clear(private)
			if err == nil {
				err = WriteJSON(*out, signed, 0o644)
			}
			result = map[string]string{"manifest": *out, "key_id": public.KeyID}
		}
	case "verify":
		if *manifest == "" {
			err = errors.New("verify requires --manifest")
			break
		}
		var signed managed.SignedReleaseManifest
		var value managed.ReleaseManifest
		if err = ReadJSON(*manifest, &signed); err == nil {
			value, err = managed.VerifyReleaseManifest(signed, managed.BuiltinReleasePublisherKeys())
		}
		if err == nil && *rpm != "" {
			err = CheckArtifact(value, *rpm)
		}
		if err == nil {
			result = map[string]any{"publisher_signature_verified": true, "artifact_verified": *rpm != "", "key_id": signed.KeyID}
		}
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "release operation failed: "+err.Error())
		return 1
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	return 0
}
