package integrity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStepsBoundBytesAndDetectReplacement(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "site")
	data := make([]byte, maxBytesPerStep+101)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "empty")
	if err := os.WriteFile(short, nil, 0600); err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(map[string]string{"a": p, "b": short, "c": p})
	defer scanner.Close()
	ctx := context.Background()
	now := time.Now()
	if _, done := scanner.Step(ctx, now); done || scanner.read != maxBytesPerStep {
		t.Fatal("step exceeded budget or completed too soon")
	}
	if err := os.Rename(short, p); err != nil {
		t.Fatal(err)
	}
	rows, done := scanner.Step(ctx, now)
	if done || rows["a"].State != "changed_during_read" || rows["b"].State != "missing" {
		t.Fatal(rows)
	}
	rows, done = scanner.Step(ctx, now)
	if !done || rows["c"].SHA256 != fmt.Sprintf("%x", sha256.Sum256(nil)) {
		t.Fatal(rows)
	}
}

func TestRejectsLinkFIFOOversize(t *testing.T) {
	dir := t.TempDir()
	link, fifo, oversize := filepath.Join(dir, "link"), filepath.Join(dir, "fifo"), filepath.Join(dir, "large")
	if err := os.Symlink(os.DevNull, link); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(oversize)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	s := NewScanner(map[string]string{"a": link, "b": fifo, "c": oversize})
	defer s.Close()
	rows, done := s.Step(context.Background(), time.Now())
	if done || len(rows) != 2 {
		t.Fatal(rows)
	}
	rows, done = s.Step(context.Background(), time.Now())
	if !done || rows["a"].State != "unreadable" || rows["b"].State != "unreadable" || rows["c"].State != "too_large" {
		t.Fatal(rows)
	}
}

func BenchmarkRepeatedScan(b *testing.B) {
	dir := b.TempDir()
	p := filepath.Join(dir, "unchanged")
	if err := os.WriteFile(p, make([]byte, 5<<20), 0600); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(5 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner(map[string]string{"a": p})
		for {
			if _, done := s.Step(context.Background(), time.Now()); done {
				break
			}
		}
		s.Close()
	}
}
