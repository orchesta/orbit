//go:build unix

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO blocks until a writer appears, so --ignore-file must be
// checked before it is opened.
func TestScanExplicitIgnoreFileFIFOIsRefusedWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "ignore.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		code, _, stderr := runFake(t, &fakeEngine{res: resultWith()}, "--path", t.TempDir(), "--ignore-file", fifo)
		done <- result{code, stderr}
	}()
	select {
	case r := <-done:
		if r.code != 2 || !strings.Contains(r.stderr, "not a regular file") {
			t.Fatalf("exit = %d, want 2 with a clear error; stderr:\n%s", r.code, r.stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("orbit scan blocked opening a FIFO given as --ignore-file")
	}
}

func TestScanBaselineFIFOIsRefusedWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "baseline.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		code, _, stderr := runFake(t, &fakeEngine{res: resultWith()}, "--path", t.TempDir(), "--baseline", fifo)
		done <- result{code, stderr}
	}()
	select {
	case r := <-done:
		if r.code != 2 || !strings.Contains(r.stderr, "not a regular file") {
			t.Fatalf("exit = %d, want 2 with a clear error; stderr:\n%s", r.code, r.stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("orbit scan blocked opening a FIFO given as --baseline")
	}
}
