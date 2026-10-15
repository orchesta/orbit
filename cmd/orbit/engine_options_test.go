package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/config"
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
	server := serverEngineOptions(config.ExploitConfig{}, logger)
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
