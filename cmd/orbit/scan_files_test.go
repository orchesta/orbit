package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aligoren/orbit/internal/domain/entity"
)

// A symlinked .orbitignore is refused with exit 2: a repository must not be
// able to point the scan at a file outside it, and silently skipping the
// file would hide that the ignores the author meant to apply were not read.
func TestScanRefusesSymlinkedDefaultIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	outside := writeFile(t, t.TempDir(), "elsewhere", "GHSA-0 accepted\n")
	if err := os.Symlink(outside, filepath.Join(dir, ".orbitignore")); err != nil {
		t.Fatal(err)
	}
	f := &fakeEngine{res: resultWith(entity.SeverityCritical)}
	code, stdout, stderr := runFake(t, f, "--path", dir)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
	}
	if stdout != "" || f.calls != 0 {
		t.Errorf("stdout %q, engine calls %d; want nothing", stdout, f.calls)
	}
	if !strings.Contains(stderr, ".orbitignore") || !strings.Contains(stderr, "not a regular file") {
		t.Errorf("stderr should explain the refusal:\n%s", stderr)
	}
}

func TestScanRefusesOversizedIgnoreFiles(t *testing.T) {
	big := "# " + strings.Repeat("x", 1<<20) + "\n"

	dir := t.TempDir()
	writeFile(t, dir, ".orbitignore", big)
	f := &fakeEngine{res: resultWith()}
	if code, _, stderr := runFake(t, f, "--path", dir); code != 2 || !strings.Contains(stderr, "larger than") {
		t.Fatalf("default: exit = %d, want 2 with a size error; stderr:\n%s", code, stderr)
	}

	explicit := writeFile(t, t.TempDir(), "ci.ignore", big)
	f = &fakeEngine{res: resultWith()}
	if code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--ignore-file", explicit); code != 2 || !strings.Contains(stderr, "larger than") {
		t.Fatalf("explicit: exit = %d, want 2 with a size error; stderr:\n%s", code, stderr)
	}
	if f.calls != 0 {
		t.Error("engine ran despite the bad ignore file")
	}
}

func TestScanExplicitIgnoreFileMustBeARegularFile(t *testing.T) {
	f := &fakeEngine{res: resultWith()}
	code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--ignore-file", t.TempDir())
	if code != 2 || !strings.Contains(stderr, "not a regular file") {
		t.Fatalf("exit = %d, want 2 for a directory; stderr:\n%s", code, stderr)
	}
}

// The user named the file, so a symlink to a regular file is followed.
func TestScanExplicitIgnoreFileMayBeASymlink(t *testing.T) {
	real := writeFile(t, t.TempDir(), "ci.ignore", "GHSA-0 accepted\n")
	link := filepath.Join(t.TempDir(), "link.ignore")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	f := &fakeEngine{res: resultWith(entity.SeverityCritical)}
	if code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--ignore-file", link); code != 0 {
		t.Fatalf("exit = %d, want 0 (finding ignored); stderr:\n%s", code, stderr)
	}
}

// A usage error never touches --out: "orbit scan --out main.go --nope" must
// not delete main.go.
func TestScanUsageErrorKeepsOutFile(t *testing.T) {
	for name, extra := range map[string][]string{
		"unknown flag":    {"--nope"},
		"invalid fail-on": {"--fail-on", "hihg"},
		"invalid format":  {"--format", "xml"},
	} {
		t.Run(name, func(t *testing.T) {
			out := writeFile(t, t.TempDir(), "main.go", "package main\n")
			args := append([]string{"--path", t.TempDir(), "--out", out}, extra...)
			if code, _, stderr := runFake(t, &fakeEngine{res: resultWith()}, args...); code != 2 {
				t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr)
			}
			if data, err := os.ReadFile(out); err != nil || string(data) != "package main\n" {
				t.Fatalf("--out file changed by a usage error: %q, %v", data, err)
			}
		})
	}
}

func TestScanReplacingReportKeepsItsMode(t *testing.T) {
	out := writeFile(t, t.TempDir(), "orbit.json", "old")
	if err := os.Chmod(out, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runFake(t, &fakeEngine{res: resultWith()}, "--path", t.TempDir(), "--format", "json", "--out", out); code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", code, stderr)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want the existing 0600", info.Mode().Perm())
	}

	fresh := filepath.Join(t.TempDir(), "new.json")
	if code, _, stderr := runFake(t, &fakeEngine{res: resultWith()}, "--path", t.TempDir(), "--format", "json", "--out", fresh); code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", code, stderr)
	}
	if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("new report mode = %v (%v), want 0644", info.Mode().Perm(), err)
	}
}

type sarifURIs struct {
	Runs []struct {
		OriginalURIBaseIDs map[string]struct{ URI string } `json:"originalUriBaseIds"`
		Results            []struct {
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func scanSARIF(t *testing.T, path string) sarifURIs {
	t.Helper()
	code, stdout, stderr := runFake(t, &fakeEngine{res: resultWith(entity.SeverityHigh)}, "--path", path, "--format", "sarif", "--fail-on", "none")
	if code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", code, stderr)
	}
	var doc sarifURIs
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// Inside the working directory (the repository root in the CI templates),
// SARIF URIs are relative to it, as code scanning expects.
func TestScanSARIFURIsRelativeToWorkingDirectory(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "services", "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	for path, want := range map[string]string{
		".":                             "package-lock.json",
		"services/api":                  "services/api/package-lock.json",
		filepath.Join(base, "services"): "services/package-lock.json",
	} {
		loc := scanSARIF(t, path).Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
		if loc.URI != want || loc.URIBaseID != "" {
			t.Errorf("--path %s: location = %+v, want uri %q without a base", path, loc, want)
		}
	}
}

// Outside it, URIs stay relative to --path, whose file URI is the base.
func TestScanSARIFURIsOutsideWorkingDirectoryUseABase(t *testing.T) {
	dir := t.TempDir()
	doc := scanSARIF(t, dir)
	loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if loc.URI != "package-lock.json" || loc.URIBaseID != "ORBITROOT" {
		t.Fatalf("location = %+v", loc)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := doc.Runs[0].OriginalURIBaseIDs["ORBITROOT"].URI, "file://"+filepath.ToSlash(resolved)+"/"; got != want {
		t.Fatalf("ORBITROOT = %q, want %q", got, want)
	}
}
