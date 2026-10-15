package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// writeBaseline writes an orbit JSON report listing the given advisories on
// npm lodash and returns its path.
func writeBaseline(t *testing.T, ids ...string) string {
	t.Helper()
	var fs []string
	for _, id := range ids {
		fs = append(fs, fmt.Sprintf(`{"id":%q,"aliases":[],"package":"lodash","version":"4.17.15","ecosystem":"npm"}`, id))
	}
	doc := `{"schema_version":1,"tool":{"name":"orbit","version":"1.0.0"},"findings":[` + strings.Join(fs, ",") + `]}`
	return writeFile(t, t.TempDir(), "orbit-baseline.json", doc)
}

func TestScanBaselineOnlyNewFindingsFail(t *testing.T) {
	// resultWith gives lodash GHSA-0 and GHSA-1, both high.
	code, stdout, stderr := runFake(t, &fakeEngine{res: resultWith(entity.SeverityHigh, entity.SeverityHigh)},
		"--path", t.TempDir(), "--baseline", writeBaseline(t, "GHSA-0"))
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (GHSA-1 is new); stderr:\n%s", code, stderr)
	}
	if !regexp.MustCompile(`(?m)^HIGH\s+GHSA-0 `).MatchString(stdout) || !regexp.MustCompile(`(?m)^HIGH \(new\)\s+GHSA-1 `).MatchString(stdout) {
		t.Errorf("table must mark only GHSA-1 as new:\n%s", stdout)
	}
	if !strings.Contains(stdout, "(2 high), 1 new") || !strings.Contains(stdout, "threshold high (new findings and malicious packages): FAILED") {
		t.Errorf("table summary:\n%s", stdout)
	}
	// The baseline was written by another orbit version (1.0.0, the tests
	// run as dev): accepted, and the version is shown.
	if !strings.Contains(stderr, "orbit: comparing with baseline ") || !strings.Contains(stderr, "(1 findings, written by orbit 1.0.0)") {
		t.Errorf("stderr lacks the baseline line:\n%s", stderr)
	}

	code, _, stderr = runFake(t, &fakeEngine{res: resultWith(entity.SeverityHigh, entity.SeverityHigh)},
		"--path", t.TempDir(), "--format", "json", "--baseline", writeBaseline(t, "GHSA-0", "GHSA-1"))
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (nothing new); stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "orbit: 1 dependencies, 1 vulnerable (2 high), 0 new") {
		t.Errorf("stderr summary:\n%s", stderr)
	}
}

func TestScanBaselineQuietHasNoBaselineLine(t *testing.T) {
	code, _, stderr := runFake(t, &fakeEngine{res: resultWith(entity.SeverityHigh)},
		"--path", t.TempDir(), "--quiet", "--baseline", writeBaseline(t, "GHSA-0"))
	if code != 0 || strings.Contains(stderr, "comparing with baseline") {
		t.Errorf("exit %d, want 0 without the baseline line; stderr:\n%s", code, stderr)
	}
}

// A report written by orbit is a valid baseline for the next run, and an
// upgrade that keeps the vulnerability does not make it new.
func TestScanBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(t.TempDir(), "orbit-baseline.json")
	if code, _, stderr := runFake(t, &fakeEngine{res: resultWith(entity.SeverityCritical)},
		"--path", dir, "--format", "json", "--fail-on", "none", "--out", base); code != 0 {
		t.Fatalf("writing the baseline: exit %d; stderr:\n%s", code, stderr)
	}
	res := resultWith(entity.SeverityCritical)
	res.Dependencies[0].CurrentVersion = "4.17.21"
	code, stdout, stderr := runFake(t, &fakeEngine{res: res}, "--path", dir, "--format", "json", "--baseline", base)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	var rep struct {
		Summary struct {
			New      int  `json:"new"`
			Baseline bool `json:"baseline"`
			Failed   bool `json:"failed"`
		} `json:"summary"`
		Findings []struct {
			New bool `json:"new"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Summary.Baseline || rep.Summary.New != 0 || rep.Summary.Failed || len(rep.Findings) != 1 || rep.Findings[0].New {
		t.Errorf("report = %+v", rep)
	}
}

func TestScanBaselineErrorsExitTwo(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, maxBaselineBytes+1); err != nil { // sparse
		t.Fatal(err)
	}
	cases := map[string]struct{ path, want string }{
		"missing":      {filepath.Join(dir, "nope.json"), "on a first run there is no baseline yet"},
		"empty":        {writeFile(t, dir, "empty.json", ""), "is empty"},
		"utf-16":       {writeFile(t, dir, "utf16.json", "\xff\xfe{\x00}\x00"), "UTF-16"},
		"truncated":    {writeFile(t, dir, "cut.json", `{"schema_version":1,"findings":[`), "not an orbit JSON report"},
		"sarif":        {writeFile(t, dir, "orbit.sarif", `{"version":"2.1.0","runs":[]}`), "no schema_version"},
		"newer schema": {writeFile(t, dir, "v2.json", `{"schema_version":2,"findings":[]}`), "schema_version 2"},
		"directory":    {dir, "not a regular file"},
		"too large":    {big, "larger than"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeEngine{res: resultWith(entity.SeverityCritical)}
			code, stdout, stderr := runFake(t, f, "--path", t.TempDir(), "--baseline", c.path)
			if code != 2 || stdout != "" || f.calls != 0 {
				t.Fatalf("exit %d, stdout %q, engine calls %d; want 2, empty, 0", code, stdout, f.calls)
			}
			if !strings.Contains(stderr, "orbit scan: baseline") || !strings.Contains(stderr, c.want) || !strings.Contains(stderr, c.path) {
				t.Errorf("stderr = %q, want %q and the path", stderr, c.want)
			}
		})
	}
}

// A bad baseline is a failed run, not a bad command line, so the --out
// report of an earlier run is removed like after any other exit 2.
func TestScanBadBaselineRemovesStaleReport(t *testing.T) {
	out := writeFile(t, t.TempDir(), "orbit.json", `{"stale":"clean report from an earlier run"}`)
	code, _, stderr := runFake(t, &fakeEngine{res: resultWith()},
		"--path", t.TempDir(), "--format", "json", "--out", out, "--baseline", filepath.Join(t.TempDir(), "nope.json"))
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("a failed run left %s behind (stat err %v)", out, err)
	}
}

// With --out naming the baseline, a failed scan would delete the baseline
// (see removeStaleReport), so the combination is refused up front, whatever
// the spelling of the two paths.
func TestScanBaselineSameFileAsOutIsRefused(t *testing.T) {
	realDir := t.TempDir()
	base := writeFile(t, realDir, "orbit-baseline.json",
		`{"schema_version":1,"tool":{"name":"orbit","version":"1.0.0"},"findings":[]}`)
	before, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	linkFile := filepath.Join(t.TempDir(), "report.json")
	if err := os.Symlink(base, linkFile); err != nil {
		t.Fatal(err)
	}
	t.Chdir(realDir)

	cases := map[string]struct{ out, baseline string }{
		"same spelling":           {base, base},
		"relative and absolute":   {"orbit-baseline.json", base},
		"absolute and relative":   {base, "./orbit-baseline.json"},
		"through a symlinked dir": {filepath.Join(linkDir, "orbit-baseline.json"), base},
		"symlink to the file":     {linkFile, base},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if name != "same spelling" && filepath.Clean(c.out) == filepath.Clean(c.baseline) {
				t.Fatalf("test bug: %q and %q are the same spelling", c.out, c.baseline)
			}
			f := &fakeEngine{res: resultWith(entity.SeverityHigh)}
			code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--format", "json", "--out", c.out, "--baseline", c.baseline)
			if code != 2 || f.calls != 0 || !strings.Contains(stderr, "orbit scan: --out and --baseline name the same file") {
				t.Fatalf("exit %d, engine calls %d; stderr:\n%s", code, f.calls, stderr)
			}
			if after, err := os.ReadFile(base); err != nil || string(after) != string(before) {
				t.Errorf("baseline changed or removed: %v", err)
			}
		})
	}

	// Another file next to the baseline is fine.
	other := filepath.Join(linkDir, "orbit.json")
	code, _, stderr := runFake(t, &fakeEngine{res: resultWith(entity.SeverityHigh)},
		"--path", t.TempDir(), "--format", "json", "--out", other, "--baseline", "orbit-baseline.json")
	if code != 1 {
		t.Fatalf("--out next to the baseline: exit %d, want 1; stderr:\n%s", code, stderr)
	}
	if after, err := os.ReadFile(base); err != nil || string(after) != string(before) {
		t.Errorf("baseline changed or removed: %v", err)
	}
}

func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.json", "a")
	b := writeFile(t, dir, "b.json", "b")
	t.Chdir(dir)
	cases := []struct {
		x, y string
		want bool
	}{
		{a, a, true},
		{a, "a.json", true},
		{a, b, false},
		{filepath.Join(dir, "new.json"), "new.json", true}, // neither exists yet
		{filepath.Join(dir, "new.json"), "other.json", false},
		{a, "new.json", false},
	}
	for _, c := range cases {
		if got := sameFile(c.x, c.y); got != c.want {
			t.Errorf("sameFile(%q, %q) = %v, want %v", c.x, c.y, got, c.want)
		}
	}
}

func TestScanEmptyBaselineFlagComparesWithNothing(t *testing.T) {
	code, stdout, stderr := runFake(t, &fakeEngine{res: resultWith(entity.SeverityHigh)}, "--path", t.TempDir(), "--baseline", "")
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr:\n%s", code, stderr)
	}
	if strings.Contains(stdout, "(new)") || regexp.MustCompile(`\d+ new\b`).MatchString(stdout) || strings.Contains(stdout, "new findings and malicious packages") {
		t.Errorf("no baseline, but the table shows new markers:\n%s", stdout)
	}
	if strings.Contains(stderr, "comparing with baseline") {
		t.Errorf("no baseline, but stderr says it compares with one:\n%s", stderr)
	}
}
