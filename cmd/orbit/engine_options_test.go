package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/config"
	"github.com/orchesta/orbit/internal/infrastructure/depsdev"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
)

const viaFixture = "../../internal/infrastructure/analyzer/npm/testdata/lock-v3-graph"

// viaCount analyzes the npm fixture with a real dependency graph and counts
// the dependencies that have Via. Latest versions are not looked up.
func viaCount(t *testing.T, opts engine.Options) int {
	t.Helper()
	opts.CheckLatest = false
	res, err := engine.New(newAnalyzerRegistry(), nil, opts).Analyze(context.Background(), viaFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Dependencies) == 0 {
		t.Fatal("no dependencies")
	}
	n := 0
	for _, d := range res.Dependencies {
		if d.Via != nil {
			n++
		}
	}
	return n
}

// The server does not store Via, so its scans do not compute it; the CLI
// shows it.
func TestServerScansSkipViaAndTheCLIKeepsIt(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	server := serverEngineOptions(config.ExploitConfig{}, config.ScannerConfig{}, logger)
	if !server.SkipVia || !server.CheckLatest {
		t.Fatalf("server options %+v, want SkipVia and CheckLatest", server)
	}
	if n := viaCount(t, server); n != 0 {
		t.Errorf("server scan: %d dependencies with Via, want none", n)
	}
	cli := cliEngineOptions(engineConfig{}, logger)
	if cli.SkipVia {
		t.Fatalf("CLI options %+v skip Via", cli)
	}
	if n := viaCount(t, cli); n == 0 {
		t.Error("CLI scan: no dependency has Via")
	}
}

// engineConfig is the only way the command line reaches the engine: each
// field turns on its own data source, and nothing is on by default.
func TestCLIEngineOptionsFollowTheEngineConfig(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	off := cliEngineOptions(engineConfig{}, logger)
	if off.CheckLatest || off.Exploit != nil || off.Licenses != nil {
		t.Fatalf("zero engineConfig: options %+v, want no registry, exploit or license lookups", off)
	}
	on := cliEngineOptions(engineConfig{checkLatest: true, exploitData: true, licenses: true}, logger)
	if !on.CheckLatest {
		t.Error("checkLatest did not reach Options.CheckLatest")
	}
	if _, ok := on.Exploit.(*exploit.Enricher); !ok {
		t.Errorf("exploitData: Options.Exploit = %T, want *exploit.Enricher", on.Exploit)
	}
	if _, ok := on.Licenses.(*depsdev.Client); !ok {
		t.Errorf("licenses: Options.Licenses = %T, want *depsdev.Client", on.Licenses)
	}
	if on.Logger != logger {
		t.Error("the logger was not passed on")
	}
}

// The server keeps SkipVia and its exploit switch whatever scanner.licenses
// says, and asks deps.dev for licenses only when scanner.licenses is on.
func TestServerEngineOptionsFollowTheConfig(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for _, licenses := range []bool{false, true} {
		opts := serverEngineOptions(config.ExploitConfig{Enabled: true}, config.ScannerConfig{Licenses: licenses}, logger)
		if !opts.SkipVia || !opts.CheckLatest {
			t.Errorf("licenses=%v: options %+v, want SkipVia and CheckLatest", licenses, opts)
		}
		if _, ok := opts.Exploit.(*exploit.Enricher); !ok {
			t.Errorf("licenses=%v: Options.Exploit = %T, want *exploit.Enricher", licenses, opts.Exploit)
		}
		_, isClient := opts.Licenses.(*depsdev.Client)
		if licenses != isClient {
			t.Errorf("licenses=%v: Options.Licenses = %T", licenses, opts.Licenses)
		}
		if opts.Logger != logger {
			t.Errorf("licenses=%v: the logger was not passed on", licenses)
		}
	}
	off := serverEngineOptions(config.ExploitConfig{}, config.ScannerConfig{Licenses: true}, logger)
	if off.Exploit != nil || !off.SkipVia {
		t.Errorf("exploit off, licenses on: options %+v, want no exploit data and SkipVia", off)
	}
	if _, ok := off.Licenses.(*depsdev.Client); !ok {
		t.Errorf("exploit off, licenses on: Options.Licenses = %T, want *depsdev.Client", off.Licenses)
	}
}
