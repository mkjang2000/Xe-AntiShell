// Package integrity measures a fixed set of agent files outside the event path.
package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"sort"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"golang.org/x/sys/unix"
)

const (
	maxTargetsPerStep = 2
	maxBytesPerStep   = 4 << 20
	maxFileSize       = 64 << 20
)

type Scanner struct {
	paths    map[string]string
	ids      []string
	index    int
	samples  map[string]contract.Sample
	file     *os.File
	original unix.Stat_t
	digest   hash.Hash
	read     int64
	buffer   [64 << 10]byte
}

func NewScanner(paths map[string]string) *Scanner {
	s := &Scanner{paths: map[string]string{}, samples: map[string]contract.Sample{}}
	for id, path := range paths {
		s.paths[id] = path
		s.ids = append(s.ids, id)
	}
	sort.Strings(s.ids)
	return s
}

func (s *Scanner) Close() {
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
	s.digest = nil
	s.read = 0
}

func (s *Scanner) open(path string) string {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return "missing"
	}
	if err != nil {
		return "unreadable"
	}
	s.file = os.NewFile(uintptr(fd), path)
	if unix.Fstat(fd, &s.original) != nil || s.original.Mode&unix.S_IFMT != unix.S_IFREG {
		return "unreadable"
	}
	if s.original.Size < 0 || s.original.Size > maxFileSize {
		return "too_large"
	}
	s.digest = sha256.New()
	return ""
}

func sameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Size == b.Size && a.Mode == b.Mode
}

func (s *Scanner) stable(path string) bool {
	var descriptor, current unix.Stat_t
	return unix.Fstat(int(s.file.Fd()), &descriptor) == nil && unix.Lstat(path, &current) == nil && sameFile(s.original, descriptor) && sameFile(s.original, current)
}

// Step accounts for bytes read even if a file changes. An unfinished file
// keeps its descriptor and hash until the next tick. Call Close on cancellation.
func (s *Scanner) Step(ctx context.Context, now time.Time) (map[string]contract.Sample, bool) {
	budget := int64(maxBytesPerStep)
	for visited := 0; visited < maxTargetsPerStep && s.index < len(s.ids) && budget > 0; visited++ {
		if ctx.Err() != nil {
			return nil, false
		}
		id := s.ids[s.index]
		path := s.paths[id]
		state := ""
		if s.file == nil {
			state = s.open(path)
		}
		if state == "" && !s.stable(path) {
			state = "changed_during_read"
		}
		for state == "" && s.read < s.original.Size && budget > 0 {
			if ctx.Err() != nil {
				return nil, false
			}
			n := min(int64(len(s.buffer)), budget, s.original.Size-s.read)
			got, err := io.ReadFull(s.file, s.buffer[:n])
			s.read += int64(got)
			budget -= int64(got)
			if err != nil {
				if s.stable(path) {
					state = "unreadable"
				} else {
					state = "changed_during_read"
				}
				break
			}
			s.digest.Write(s.buffer[:got])
		}
		if state == "" && s.read < s.original.Size {
			break
		}
		sample := contract.Sample{State: state, MeasuredAt: now.UTC()}
		if state == "" {
			if s.stable(path) {
				sample.State = "measured"
				sample.SHA256 = hex.EncodeToString(s.digest.Sum(nil))
			} else {
				sample.State = "changed_during_read"
			}
		}
		s.samples[id] = sample
		s.Close()
		s.index++
	}
	return s.samples, s.index == len(s.ids)
}
