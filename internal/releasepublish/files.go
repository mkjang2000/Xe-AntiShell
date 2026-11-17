// Package releasepublish prepares and signs public RPM release metadata. It is
// a build tool, not part of the central or agent update execution path.
package releasepublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type queryOutput struct{ buffer []byte }

func (q *queryOutput) Write(data []byte) (int, error) {
	if len(q.buffer)+len(data) > 4096 {
		return 0, errors.New("RPM query output exceeds limit")
	}
	q.buffer = append(q.buffer, data...)
	return len(data), nil
}

func InspectRPM(ctx context.Context, path string) (managed.RPMPackage, string, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/usr/bin/rpm", "-qp", "--queryformat", "%{NAME}\\n%{EPOCHNUM}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n", "--", path)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var output queryOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if command.Run() != nil {
		return managed.RPMPackage{}, "", errors.New("cannot inspect agent RPM metadata")
	}
	return managed.ParseRPMMetadata(output.buffer)
}

func ArtifactFacts(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > managed.MaxUpdateArtifactBytes {
		return "", 0, errors.New("RPM must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, errors.New("cannot read RPM")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", 0, errors.New("RPM changed during verification")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, managed.MaxUpdateArtifactBytes+1))
	if err != nil || size != info.Size() || size > managed.MaxUpdateArtifactBytes {
		return "", 0, errors.New("RPM changed or exceeded size limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func Prepare(ctx context.Context, path string, now time.Time) (managed.ReleaseManifest, error) {
	pack, major, err := InspectRPM(ctx, path)
	if err != nil {
		return managed.ReleaseManifest{}, err
	}
	hash, size, err := ArtifactFacts(path)
	if err != nil {
		return managed.ReleaseManifest{}, err
	}
	m := managed.ReleaseManifest{SchemaVersion: managed.SchemaVersion, ArtifactName: filepath.Base(path), Package: pack, OSFamily: "rhel", OSMajor: major, SHA256: hash, Size: size, PublishedAt: now.UTC()}
	if err := m.Validate(); err != nil {
		return managed.ReleaseManifest{}, err
	}
	return m, nil
}

func CheckArtifact(manifest managed.ReleaseManifest, path string) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	hash, size, err := ArtifactFacts(path)
	if err != nil {
		return err
	}
	if hash != manifest.SHA256 || size != manifest.Size {
		return errors.New("RPM does not match release manifest")
	}
	return nil
}

func ReadJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > managed.MaxReleaseManifestBytes {
		return errors.New("invalid release metadata file")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("cannot read release metadata")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, managed.MaxReleaseManifestBytes+1))
	if err != nil || len(data) > managed.MaxReleaseManifestBytes {
		return errors.New("release metadata exceeds limit")
	}
	if managed.DecodeStrict(data, managed.MaxReleaseManifestBytes, value) != nil {
		return errors.New("invalid release metadata JSON")
	}
	return nil
}

func WriteJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("cannot encode release metadata")
	}
	data = append(data, '\n')
	return writeExclusive(path, data, mode)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".xeas-release-")
	if err != nil {
		return errors.New("cannot stage release file")
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot persist release file")
	}
	if os.Link(file.Name(), path) != nil {
		return errors.New("release output already exists or cannot be published")
	}
	dir, err := os.Open(directory)
	if err != nil {
		return errors.New("cannot sync release directory")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errors.New("cannot sync release directory")
	}
	return nil
}
