package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/buildinfo"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
)

// fakeEngine stands in for engine.Engine: it returns a canned result and
// records how it was built and called.
type fakeEngine struct {
	res   *engine.Result
	err   error
	block bool // wait for ctx to end, then return ctx.Err()

	logMsg  string // if set, logged at warning level with logPath as "path"
	logPath string
	logger  *slog.Logger

	calls       int
	root        string
	checkLatest bool
	exploitData bool
	licenses    bool
	deadline    time.Time
}

func (f *fakeEngine) Analyze(ctx context.Context, root string) (*engine.Result, error) {
	f.calls++
	f.root = root
	f.deadline, _ = ctx.Deadline()
	if f.logMsg != "" {
		f.logger.Warn(f.logMsg, slog.String("path", f.logPath))
	}
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.res, f.err
}

var testNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func (f *fakeEngine) deps() scanDeps {
	return scanDeps{
		newEngine: func(ec engineConfig, logger *slog.Logger) analyzerEngine {
			f.checkLatest = ec.checkLatest
			f.exploitData = ec.exploitData
			f.licenses = ec.licenses
			f.logger = logger
			return f
		},
		now: func() time.Time { return testNow },
	}
}

// resultWith returns a result with one npm dependency carrying one
// vulnerability per given severity (IDs GHSA-0, GHSA-1, ...).
func resultWith(sevs ...entity.Severity) *engine.Result {
	dep := entity.NewDependency(uuid.Nil, uuid.Nil, "lodash", "4.17.20", "package-lock.json", entity.EcosystemNpm)
	res := &engine.Result{Dependencies: []*entity.Dependency{dep}, Manifests: []string{"package-lock.json"}}
	for i, s := range sevs {
		res.Vulnerabilities = append(res.Vulnerabilities, entity.NewVulnerability(dep.ID, fmt.Sprintf("GHSA-%d", i), "bad thing", s))
	}
	if len(sevs) > 0 {
		res.VulnerableDeps = 1
	}
	return res
}

func runFake(t *testing.T, f *fakeEngine, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runScan(context.Background(), args, &out, &errOut, f.deps())
	return code, out.String(), errOut.String()
}

func TestScanBelowThresholdExitsZero(t *testing.T) {
	dir := t.TempDir()
	f := &fakeEngine{res: resultWith(entity.SeverityMedium, entity.SeverityLow)}
	code, stdout, stderr := runFake(t, f, "--path", dir, "--fail-on", "high")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	if f.root != dir {
		t.Errorf("analyzed %q, want %q", f.root, dir)
	}
	if !strings.Contains(stdout, "GHSA-0") {
		t.Errorf("table on stdout lacks the finding:\n%s", stdout)
	}
	if !strings.Contains(stdout, "threshold high: passed") {
		t.Errorf("table on stdout lacks the summary:\n%s", stdout)
	}
}

// A table on stdout already ends with the counts and the threshold verdict,
// so they are not repeated on stderr. Any other output keeps the summary on
// stderr, where the CI log shows it.
func TestScanPrintsTheSummaryOnce(t *testing.T) {
	f := &fakeEngine{res: resultWith(entity.SeverityHigh)}
	_, stdout, stderr := runFake(t, f, "--path", t.TempDir())
	if n := strings.Count(stdout+stderr, "threshold high: FAILED"); n != 1 {
		t.Errorf("table on stdout: summary printed %d times, want 1\nstdout:\n%s\nstderr:\n%s", n, stdout, stderr)
	}

	out := filepath.Join(t.TempDir(), "report.txt")
	_, _, stderr = runFake(t, f, "--path", t.TempDir(), "--out", out)
	if !strings.Contains(stderr, "orbit: threshold high: FAILED") {
		t.Errorf("table to --out: stderr lacks the summary:\n%s", stderr)
	}

	_, _, stderr = runFake(t, f, "--path", t.TempDir(), "--format", "json")
	if !strings.Contains(stderr, "orbit: threshold high: FAILED") {
		t.Errorf("json on stdout: stderr lacks the summary:\n%s", stderr)
	}
}

func TestScanAboveThresholdExitsOne(t *testing.T) {
	f := &fakeEngine{res: resultWith(entity.SeverityLow, entity.SeverityHigh)}
	code, stdout, stderr := runFake(t, f, "--path", t.TempDir())
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (default --fail-on high); stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "threshold high: FAILED") {
		t.Errorf("table on stdout lacks the failed summary:\n%s", stdout)
	}
}

func TestScanFailOnLevels(t *testing.T) {
	cases := []struct {
		failOn string
		sev    entity.Severity
		want   int
	}{
		{"critical", entity.SeverityHigh, 0},
		{"critical", entity.SeverityCritical, 1},
		{"medium", entity.SeverityMedium, 1},
		{"low", entity.SeverityMedium, 1},
		{"low", entity.SeverityUnknown, 0},
		{"unknown", entity.SeverityUnknown, 1},
		{"none", entity.SeverityCritical, 0},
		{"HIGH", entity.SeverityHigh, 1},
	}
	for _, c := range cases {
		t.Run(c.failOn+"/"+string(c.sev), func(t *testing.T) {
			f := &fakeEngine{res: resultWith(c.sev)}
			code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--fail-on", c.failOn, "--quiet")
			if code != c.want {
				t.Fatalf("exit = %d, want %d; stderr:\n%s", code, c.want, stderr)
			}
		})
	}
}

func TestScanLookupErrorExitsTwoWithEmptyStdout(t *testing.T) {
	for _, format := range []string{"table", "json", "sarif", "junit"} {
		t.Run(format, func(t *testing.T) {
			// The engine returns the dependencies alongside a failed lookup;
			// that must never be reported as a clean scan.
			f := &fakeEngine{
				res: resultWith(),
				err: fmt.Errorf("%w: osv.dev returned 503", engine.ErrVulnerabilityCheck),
			}
			code, stdout, stderr := runFake(t, f, "--path", t.TempDir(), "--format", format, "--fail-on", "none")
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout must be empty on error, got:\n%s", stdout)
			}
			if !strings.Contains(stderr, "osv.dev returned 503") {
				t.Errorf("stderr lacks the cause:\n%s", stderr)
			}
		})
	}
}

func TestScanTimeoutExitsTwo(t *testing.T) {
	f := &fakeEngine{block: true}
	start := time.Now()
	code, stdout, stderr := runFake(t, f, "--path", t.TempDir(), "--timeout", "20ms")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty on error, got:\n%s", stdout)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("timeout not applied")
	}
	if !strings.Contains(stderr, "deadline") {
		t.Errorf("stderr should name the deadline:\n%s", stderr)
	}
}

func TestScanCanceledContextExitsTwo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeEngine{block: true}
	var out, errOut bytes.Buffer
	if code := runScan(ctx, []string{"--path", t.TempDir()}, &out, &errOut, f.deps()); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if out.Len() != 0 {
		t.Errorf("stdout must be empty, got:\n%s", out.String())
	}
}

func TestScanDefaultTimeoutIsTenMinutes(t *testing.T) {
	f := &fakeEngine{res: resultWith()}
	before := time.Now()
	if code, _, stderr := runFake(t, f, "--path", t.TempDir()); code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", code, stderr)
	}
	if d := f.deadline.Sub(before); d < 9*time.Minute || d > 11*time.Minute {
		t.Errorf("deadline in %v, want ~10m", d)
	}
}

func TestScanBadFlagsExitTwo(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]string{
		"invalid fail-on":       {"--path", dir, "--fail-on", "hihg"},
		"empty fail-on":         {"--path", dir, "--fail-on", ""},
		"invalid format":        {"--path", dir, "--format", "xml"},
		"invalid sbom format":   {"--path", dir, "--format", "cyclonedx-xml"},
		"unknown flag":          {"--path", dir, "--nope"},
		"stray argument":        {"--path", dir, "extra"},
		"zero timeout":          {"--path", dir, "--timeout", "0s"},
		"missing path":          {"--path", filepath.Join(dir, "missing")},
		"path is a file":        {"--path", writeFile(t, dir, "file.txt", "x")},
		"missing ignore file":   {"--path", dir, "--ignore-file", filepath.Join(dir, "nope")},
		"kev gate without data": {"--path", dir, "--fail-on-kev", "--no-exploit-data"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeEngine{res: resultWith(entity.SeverityCritical)}
			code, stdout, stderr := runFake(t, f, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout must be empty, got:\n%s", stdout)
			}
			if f.calls != 0 {
				t.Errorf("engine ran despite a bad flag")
			}
			if strings.TrimSpace(stderr) == "" {
				t.Errorf("no message on stderr")
			}
		})
	}
}

func TestScanSarifToFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(t.TempDir(), "orbit.sarif")
	f := &fakeEngine{res: resultWith(entity.SeverityHigh)}
	code, stdout, stderr := runFake(t, f, "--path", dir, "--format", "sarif", "--out", out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty with --out, got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "1 dependencies, 1 vulnerable") || !strings.Contains(stderr, "threshold high: FAILED") {
		t.Errorf("stderr lacks the summary:\n%s", stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("report file: %v", err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, data)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 || log.Runs[0].Results[0].RuleID != "GHSA-0" {
		t.Errorf("unexpected SARIF: %s", data)
	}
	if d := log.Runs[0].Tool.Driver; d.Name != "orbit" || d.Version != buildinfo.Version {
		t.Errorf("tool = %+v, want orbit %s", d, buildinfo.Version)
	}
}

func TestScanJSONAndJUnitToStdout(t *testing.T) {
	f := &fakeEngine{res: resultWith(entity.SeverityLow)}
	code, stdout, stderr := runFake(t, f, "--path", t.TempDir(), "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", code, stderr)
	}
	var rep struct {
		Findings []struct{ ID string } `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || len(rep.Findings) != 1 {
		t.Fatalf("stdout is not the JSON report (%v):\n%s", err, stdout)
	}
	if !strings.Contains(stderr, "threshold high: passed") {
		t.Errorf("stderr lacks the summary:\n%s", stderr)
	}

	code, stdout, _ = runFake(t, &fakeEngine{res: resultWith(entity.SeverityLow)}, "--path", t.TempDir(), "--format", "junit")
	if code != 0 || !strings.HasPrefix(stdout, "<?xml") {
		t.Fatalf("junit: exit %d, stdout:\n%s", code, stdout)
	}
}

func TestScanOutputFileErrorExitsTwo(t *testing.T) {
	out := filepath.Join(t.TempDir(), "no-such-dir", "report.json")
	f := &fakeEngine{res: resultWith(entity.SeverityLow)}
	code, stdout, stderr := runFake(t, f, "--path", t.TempDir(), "--format", "json", "--out", out)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty, got:\n%s", stdout)
	}
}

func TestScanIgnoredFindingDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".orbitignore", "GHSA-0 reviewed, not reachable\n")
	f := &fakeEngine{res: resultWith(entity.SeverityCritical)}
	code, stdout, stderr := runFake(t, f, "--path", dir)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (finding is ignored); stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "(ignored)") {
		t.Errorf("table should mark the finding ignored:\n%s", stdout)
	}
}

func TestScanExplicitIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	ignore := writeFile(t, t.TempDir(), "ci.ignore", "GHSA-0 expires=2027-01-01 accepted\n")
	f := &fakeEngine{res: resultWith(entity.SeverityCritical)}
	if code, _, stderr := runFake(t, f, "--path", dir, "--ignore-file", ignore); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}

	// An expired entry no longer applies.
	expired := writeFile(t, t.TempDir(), "old.ignore", "GHSA-0 expires=2026-01-01 accepted\n")
	f = &fakeEngine{res: resultWith(entity.SeverityCritical)}
	code, stdout, stderr := runFake(t, f, "--path", dir, "--ignore-file", expired)
	if code != 1 {
		t.Fatalf("expired: exit = %d, want 1; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "expired") {
		t.Errorf("the table should warn about the expired entry:\n%s", stdout)
	}
}

func TestScanEmptyIgnoreFileFlagDisablesDefault(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".orbitignore", "GHSA-0 accepted\n")
	f := &fakeEngine{res: resultWith(entity.SeverityCritical)}
	if code, _, stderr := runFake(t, f, "--path", dir, "--ignore-file", ""); code != 1 {
		t.Fatalf("exit = %d, want 1 (default ignore file disabled); stderr:\n%s", code, stderr)
	}
}

func TestScanHelpExitsZero(t *testing.T) {
	f := &fakeEngine{res: resultWith()}
	code, stdout, stderr := runFake(t, f, "-h")
	if code != 0 || stdout != "" || f.calls != 0 || !strings.Contains(stderr, "-fail-on") {
		t.Fatalf("code %d, stdout %q, calls %d, stderr:\n%s", code, stdout, f.calls, stderr)
	}
}

func TestScanIgnoreParseErrorExitsTwo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".orbitignore", "GHSA-0 expires=tomorrow\n")
	f := &fakeEngine{res: resultWith(entity.SeverityLow)}
	code, stdout, stderr := runFake(t, f, "--path", dir)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
	}
	if stdout != "" || f.calls != 0 {
		t.Errorf("stdout %q, engine calls %d; want nothing", stdout, f.calls)
	}
	if !strings.Contains(stderr, "line 1") {
		t.Errorf("stderr should carry the parse error:\n%s", stderr)
	}
}

func TestScanOutdatedFlagEnablesLatestCheck(t *testing.T) {
	f := &fakeEngine{res: resultWith()}
	runFake(t, f, "--path", t.TempDir())
	if f.checkLatest {
		t.Errorf("registries queried without --outdated")
	}
	f = &fakeEngine{res: resultWith()}
	runFake(t, f, "--path", t.TempDir(), "--outdated")
	if !f.checkLatest {
		t.Errorf("--outdated did not enable the latest-version check")
	}
}

func TestScanQuietKeepsSummaryAndWarnings(t *testing.T) {
	res := resultWith(entity.SeverityHigh)
	res.Warnings = []string{"package.json has no lockfile"}
	f := &fakeEngine{res: res}
	code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--format", "json", "--quiet")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "threshold high: FAILED") || !strings.Contains(stderr, "package.json has no lockfile") {
		t.Errorf("quiet must keep summary and warnings:\n%s", stderr)
	}
	if strings.Contains(stderr, "scanning") {
		t.Errorf("quiet must drop progress lines:\n%s", stderr)
	}
}

func TestDispatch(t *testing.T) {
	newCmds := func(served, scanned *int, scanArgs *[]string) commands {
		return commands{
			serve: func() int { *served++; return 0 },
			scan: func(args []string, _, _ io.Writer) int {
				*scanned++
				*scanArgs = args
				return 7
			},
		}
	}

	t.Run("no arguments runs the server", func(t *testing.T) {
		var served, scanned int
		var args []string
		var out, errOut bytes.Buffer
		if code := dispatch(nil, &out, &errOut, newCmds(&served, &scanned, &args)); code != 0 || served != 1 || scanned != 0 {
			t.Fatalf("code %d, served %d, scanned %d", code, served, scanned)
		}
	})
	t.Run("serve runs the server", func(t *testing.T) {
		var served, scanned int
		var args []string
		var out, errOut bytes.Buffer
		if code := dispatch([]string{"serve"}, &out, &errOut, newCmds(&served, &scanned, &args)); code != 0 || served != 1 {
			t.Fatalf("code %d, served %d", code, served)
		}
	})
	t.Run("scan passes the rest of the arguments", func(t *testing.T) {
		var served, scanned int
		var args []string
		var out, errOut bytes.Buffer
		code := dispatch([]string{"scan", "--path", "x"}, &out, &errOut, newCmds(&served, &scanned, &args))
		if code != 7 || scanned != 1 || served != 0 || strings.Join(args, " ") != "--path x" {
			t.Fatalf("code %d, scanned %d, served %d, args %q", code, scanned, served, args)
		}
	})
	t.Run("version prints the version", func(t *testing.T) {
		var served, scanned int
		var args []string
		var out, errOut bytes.Buffer
		code := dispatch([]string{"version"}, &out, &errOut, newCmds(&served, &scanned, &args))
		if code != 0 || out.String() != "orbit "+buildinfo.Version+"\n" || served+scanned != 0 {
			t.Fatalf("code %d, stdout %q", code, out.String())
		}
	})
	t.Run("help prints usage and exits 0", func(t *testing.T) {
		var served, scanned int
		var args []string
		var out, errOut bytes.Buffer
		code := dispatch([]string{"--help"}, &out, &errOut, newCmds(&served, &scanned, &args))
		if code != 0 || served+scanned != 0 || !strings.Contains(out.String(), "orbit scan") {
			t.Fatalf("code %d, stdout %q", code, out.String())
		}
	})
	t.Run("unknown command prints usage and exits 2", func(t *testing.T) {
		var served, scanned int
		var args []string
		var out, errOut bytes.Buffer
		code := dispatch([]string{"scna"}, &out, &errOut, newCmds(&served, &scanned, &args))
		if code != 2 || served+scanned != 0 || out.Len() != 0 || !strings.Contains(errOut.String(), "Usage") {
			t.Fatalf("code %d, stdout %q, stderr %q", code, out.String(), errOut.String())
		}
	})
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanFailureRemovesStaleReport(t *testing.T) {
	cases := map[string]struct {
		engine *fakeEngine
		args   []string
	}{
		"engine error": {
			engine: &fakeEngine{res: resultWith(), err: fmt.Errorf("%w: osv.dev returned 503", engine.ErrVulnerabilityCheck)},
		},
		// Flags were valid, so --out is the report the run was meant to write.
		"bad ignore file": {
			engine: &fakeEngine{res: resultWith()},
			args:   []string{"--ignore-file", "/nonexistent/orbit.ignore"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out := writeFile(t, t.TempDir(), "orbit.sarif", `{"stale":"clean report from an earlier run"}`)
			args := append([]string{"--path", t.TempDir(), "--format", "sarif", "--out", out}, c.args...)
			code, stdout, stderr := runFake(t, c.engine, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout must be empty, got:\n%s", stdout)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("a failed run left %s behind (stat err %v)", out, err)
			}
		})
	}
}

func TestScanReplacesReportFileAtomically(t *testing.T) {
	dir := t.TempDir()
	out := writeFile(t, dir, "orbit.json", "old report "+strings.Repeat(".", 64*1024))
	f := &fakeEngine{res: resultWith(entity.SeverityLow)}
	code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--format", "json", "--out", out)
	if code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", code, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct{ ID string } `json:"findings"`
	}
	if err := json.Unmarshal(data, &rep); err != nil || len(rep.Findings) != 1 || rep.Findings[0].ID != "GHSA-0" {
		t.Fatalf("report not replaced cleanly (%v):\n%s", err, data)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("report mode = %v (%v), want 0644", info.Mode().Perm(), err)
	}
	assertNoTempFiles(t, dir)
}

func TestScanUnwritableReportLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report") // a directory: the rename onto it fails
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fakeEngine{res: resultWith(entity.SeverityLow)}
	code, stdout, stderr := runFake(t, f, "--path", t.TempDir(), "--format", "json", "--out", out)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty, got:\n%s", stdout)
	}
	if info, err := os.Stat(out); err != nil || !info.IsDir() {
		t.Errorf("--out directory must be left alone (stat %v, %v)", info, err)
	}
	assertNoTempFiles(t, dir)
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, ".orbit-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) > 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

var rawCICommand = regexp.MustCompile(`(?i)##(vso)?\[`)

// assertNoCICommands fails if out has a log command a CI agent would run:
// Azure's ##vso[ or ##[ anywhere, or GitHub's :: at a line start. The agents
// split lines at CR as well as LF.
func assertNoCICommands(t *testing.T, name, out string) {
	t.Helper()
	for _, line := range strings.FieldsFunc(out, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if rawCICommand.MatchString(line) {
			t.Errorf("%s: line carries a raw log command: %q", name, line)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "::") {
			t.Errorf("%s: line starts a workflow command: %q", name, line)
		}
	}
}

const (
	hostileIgnoreID = "GHSA-x##vso[task.prependpath]/x" // a line starting with # is a comment
	hostileManifest = "a\n::error::x/package-lock.json"
	hostileSummary  = "##vso[task.complete result=Succeeded]done ##[error]e"
)

// hostileResult has repository- and osv.dev-controlled text that carries CI
// log commands, and logs one through the CLI's logger.
func hostileFake() *fakeEngine {
	dep := entity.NewDependency(uuid.Nil, uuid.Nil, "lodash", "4.17.20", hostileManifest, entity.EcosystemNpm)
	res := &engine.Result{Dependencies: []*entity.Dependency{dep}, Manifests: []string{hostileManifest}}
	res.Vulnerabilities = []*entity.Vulnerability{entity.NewVulnerability(dep.ID, "GHSA-1", hostileSummary, entity.SeverityHigh)}
	res.Warnings = []string{"failed to parse manifest " + hostileManifest + ": ##vso[task.setvariable variable=x]1"}
	return &fakeEngine{res: res, logMsg: "failed to read manifest", logPath: "b\n::warning::y ##VSO[task.setvariable variable=z]2"}
}

func TestScanNeutralisesCILogCommands(t *testing.T) {
	for _, format := range []string{"table", "json", "sarif", "junit", "cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, ".orbitignore", hostileIgnoreID+" never matches\n")
			code, stdout, stderr := runFake(t, hostileFake(), "--path", dir, "--format", format, "--verbose")
			if code != 1 {
				t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr)
			}
			assertNoCICommands(t, "stdout", stdout)
			assertNoCICommands(t, "stderr", stderr)
			// The warning is in the table on stdout, or in the summary on stderr
			// for the other formats.
			for _, want := range []string{"unused ignore entry GHSA-x# #vso[task.prependpath]/x", "failed to read manifest"} {
				if !strings.Contains(stdout+stderr, want) {
					t.Errorf("output lacks %q:\nstdout:\n%s\nstderr:\n%s", want, stdout, stderr)
				}
			}
			switch format {
			case "json":
				var rep struct {
					Findings []struct{ Summary, Manifest string } `json:"findings"`
					Summary  struct{ Warnings []string }          `json:"summary"`
				}
				if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
					t.Fatal(err)
				}
				if rep.Findings[0].Summary != hostileSummary || rep.Findings[0].Manifest != hostileManifest {
					t.Errorf("JSON decodes to %q / %q, want the original text", rep.Findings[0].Summary, rep.Findings[0].Manifest)
				}
				if !slices.Contains(rep.Summary.Warnings, "unused ignore entry "+hostileIgnoreID) {
					t.Errorf("JSON warnings = %q", rep.Summary.Warnings)
				}
			case "sarif":
				var log struct {
					Runs []struct {
						Tool struct {
							Driver struct {
								Rules []struct {
									Short struct{ Text string } `json:"shortDescription"`
								} `json:"rules"`
							} `json:"driver"`
						} `json:"tool"`
					} `json:"runs"`
				}
				if err := json.Unmarshal([]byte(stdout), &log); err != nil {
					t.Fatal(err)
				}
				if got := log.Runs[0].Tool.Driver.Rules[0].Short.Text; got != hostileSummary {
					t.Errorf("SARIF decodes to %q, want %q", got, hostileSummary)
				}
			}
		})
	}
}

func TestScanErrorLinesAreNeutralised(t *testing.T) {
	f := &fakeEngine{err: errors.New("open c\n::error::z ##vso[task.setvariable variable=q]1")}
	code, _, stderr := runFake(t, f, "--path", t.TempDir())
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	assertNoCICommands(t, "stderr", stderr)
	if !strings.Contains(stderr, "> ::error::z # #vso[task.setvariable variable=q]1") {
		t.Errorf("stderr should show the neutralised line:\n%s", stderr)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestScanStdoutWriteFailureExitsTwo(t *testing.T) {
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			var errOut bytes.Buffer
			f := &fakeEngine{res: resultWith(entity.SeverityLow)}
			code := runScan(context.Background(), []string{"--path", t.TempDir(), "--format", format}, failingWriter{}, &errOut, f.deps())
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr:\n%s", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), "broken pipe") {
				t.Errorf("stderr lacks the cause:\n%s", errOut.String())
			}
		})
	}
}

// kevResult is a medium finding listed in CISA KEV with exploit data
// collected, as the real engine reports jquery@3.4.1 (CVE-2020-11023).
func kevResult() *engine.Result {
	res := resultWith(entity.SeverityMedium)
	added := time.Date(2025, 1, 23, 0, 0, 0, 0, time.UTC)
	epss, pct := 0.84887, 0.9971
	v := res.Vulnerabilities[0]
	v.KEV, v.KEVDateAdded, v.EPSS, v.EPSSPercentile = true, &added, &epss, &pct
	res.Exploit = &exploit.Result{
		KEV:  exploit.SourceResult{Status: exploit.StatusOK, Version: "2026.10.14"},
		EPSS: exploit.SourceResult{Status: exploit.StatusOK, Version: "2026-10-14"},
	}
	return res
}

// kevUnavailable is kevResult after the KEV download failed: no KEV
// status, a warning from the engine.
func kevUnavailable() *engine.Result {
	res := kevResult()
	res.Vulnerabilities[0].KEV, res.Vulnerabilities[0].KEVDateAdded = false, nil
	res.Exploit.KEV = exploit.SourceResult{Status: exploit.StatusFailed, Err: errors.New("fetch KEV catalog: dial tcp: i/o timeout")}
	res.Warnings = res.Exploit.Warnings()
	return res
}

func TestScanAsksForExploitDataUnlessTurnedOff(t *testing.T) {
	f := &fakeEngine{res: resultWith()}
	runFake(t, f, "--path", t.TempDir())
	if !f.exploitData {
		t.Error("exploit data must be on by default")
	}
	f = &fakeEngine{res: resultWith()}
	runFake(t, f, "--path", t.TempDir(), "--no-exploit-data")
	if f.exploitData {
		t.Error("--no-exploit-data did not turn exploit data off")
	}
}

func TestScanFailOnKEV(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    int
		verdict string
	}{
		{"severity gate only", []string{"--fail-on", "high"}, 0, "threshold high: passed"},
		{"kev gate", []string{"--fail-on", "high", "--fail-on-kev"}, 1, "fail on KEV: FAILED"},
		{"kev gate without a threshold", []string{"--fail-on", "none", "--fail-on-kev"}, 1, "fail on KEV: FAILED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runFake(t, &fakeEngine{res: kevResult()}, append([]string{"--path", t.TempDir()}, tc.args...)...)
			if code != tc.want {
				t.Fatalf("exit = %d, want %d; stderr:\n%s", code, tc.want, stderr)
			}
			if !strings.Contains(stdout, tc.verdict) || !strings.Contains(stdout, "1 known exploited (CISA KEV)") {
				t.Fatalf("table lacks %q and the KEV count:\n%s", tc.verdict, stdout)
			}
		})
	}
}

func TestScanFailOnKEVPassesAnIgnoredFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".orbitignore", "GHSA-0 mitigated by CSP, see SEC-12\n")
	code, stdout, stderr := runFake(t, &fakeEngine{res: kevResult()}, "--path", dir, "--fail-on-kev")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (the KEV finding is ignored); stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "fail on KEV: passed") {
		t.Fatalf("table:\n%s", stdout)
	}
}

// --fail-on-kev cannot be checked without the catalog: exit 2, no report.
func TestScanFailOnKEVWithoutTheCatalogExitsTwo(t *testing.T) {
	out := filepath.Join(t.TempDir(), "orbit.json")
	if err := os.WriteFile(out, []byte(`{"stale":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runFake(t, &fakeEngine{res: kevUnavailable()}, "--path", t.TempDir(), "--fail-on-kev", "--format", "json", "--out", out)
	if code != 2 || stdout != "" {
		t.Fatalf("exit = %d, stdout %q; want 2 and nothing", code, stdout)
	}
	if !strings.Contains(stderr, "--fail-on-kev") || !strings.Contains(stderr, "i/o timeout") {
		t.Fatalf("stderr lacks the cause:\n%s", stderr)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale report kept: %v", err)
	}
}

func TestScanExploitDataFailureIsOnlyAWarning(t *testing.T) {
	code, stdout, stderr := runFake(t, &fakeEngine{res: kevUnavailable()}, "--path", t.TempDir(), "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (medium is below --fail-on high); stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "warning: exploit data: the CISA KEV catalog could not be loaded") {
		t.Fatalf("stderr lacks the warning:\n%s", stderr)
	}
	if !strings.Contains(stdout, `"kev": "failed"`) {
		t.Fatalf("JSON lacks exploit_data.kev failed:\n%s", stdout)
	}
}

// The threshold line covers the severity gate only: two medium findings
// pass --fail-on high even though the KEV one fails --fail-on-kev.
func TestScanThresholdLineIgnoresTheKEVGate(t *testing.T) {
	res := kevResult()
	more := resultWith(entity.SeverityMedium, entity.SeverityMedium).Vulnerabilities[1]
	more.DependencyID = res.Dependencies[0].ID
	res.Vulnerabilities = append(res.Vulnerabilities, more)
	code, stdout, stderr := runFake(t, &fakeEngine{res: res}, "--path", t.TempDir(), "--fail-on", "high", "--fail-on-kev")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "(2 medium)") || !strings.Contains(stdout, "threshold high: passed\nfail on KEV: FAILED\n") {
		t.Fatalf("table:\n%s", stdout)
	}
}

// With the KEV catalog the --fail-on-kev gate can be checked, so a failed
// EPSS lookup is only a warning: exit 1 for the KEV finding, not 2.
func TestScanFailOnKEVWithoutEPSSStillChecksTheGate(t *testing.T) {
	res := kevResult()
	res.Vulnerabilities[0].EPSS, res.Vulnerabilities[0].EPSSPercentile = nil, nil
	res.Exploit.EPSS = exploit.SourceResult{Status: exploit.StatusFailed, Err: errors.New("query EPSS: HTTP 429, rate limited by api.first.org")}
	res.Warnings = res.Exploit.Warnings()
	code, stdout, stderr := runFake(t, &fakeEngine{res: res}, "--path", t.TempDir(), "--fail-on-kev")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "fail on KEV: FAILED") || !strings.Contains(stdout+stderr, "warning: exploit data: FIRST EPSS scores could not be loaded") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// hostileRecommendations has CI log commands in the text the
// recommendations show: a Via name (upgrade row), an advisory without a
// fix (no-fix note) and a malicious advisory (removal note).
func hostileRecommendations() *fakeEngine {
	qs := entity.NewDependency(uuid.Nil, uuid.Nil, "qs", "6.7.0", "package-lock.json", entity.EcosystemNpm)
	qs.Via = []string{"##vso[task.prependpath]/via"}
	evil := entity.NewDependency(uuid.Nil, uuid.Nil, "evil-pkg", "1.0.0", "package-lock.json", entity.EcosystemNpm)
	fixed := entity.NewVulnerability(qs.ID, "GHSA-fixed", "bad thing", entity.SeverityHigh)
	fix := "6.7.3"
	fixed.FixedVersion = &fix
	res := &engine.Result{Dependencies: []*entity.Dependency{qs, evil}, Manifests: []string{"package-lock.json"}, VulnerableDeps: 2}
	res.Vulnerabilities = []*entity.Vulnerability{
		fixed,
		entity.NewVulnerability(qs.ID, "GHSA-n##[error]nofix", "no fix", entity.SeverityLow),
		entity.NewVulnerability(evil.ID, "MAL-2025-1##vso[task.complete result=Succeeded]", "malicious", entity.SeverityCritical),
	}
	return &fakeEngine{res: res}
}

// A table report is neutralised wherever it goes: CI jobs print an --out
// file as readily as stdout.
func TestScanNeutralisesRecommendationsInTableReports(t *testing.T) {
	neutralised := []string{
		"# #vso[task.prependpath]/via",                                                 // Via
		"no known fix for GHSA-n# #[error]nofix",                                       // no-fix note
		"remove evil-pkg@1.0.0: reported as malicious (MAL-2025-1# #vso[task.complete", // malicious note
	}
	for _, out := range []string{"-", "file"} {
		t.Run(out, func(t *testing.T) {
			dir := t.TempDir()
			args := []string{"--path", dir}
			file := filepath.Join(t.TempDir(), "report.txt")
			if out == "file" {
				args = append(args, "--out", file)
			}
			code, stdout, stderr := runFake(t, hostileRecommendations(), args...)
			if code != 1 {
				t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr)
			}
			assertNoCICommands(t, "stdout", stdout)
			assertNoCICommands(t, "stderr", stderr)
			table := stdout
			if out == "file" {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				table = string(data)
				assertNoCICommands(t, "--out file", table)
			}
			for _, want := range neutralised {
				if !strings.Contains(table, want) {
					t.Errorf("table lacks %q:\n%s", want, table)
				}
			}
		})
	}
}
