package ci

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// fakeTool stands in for docker and orbit. It logs its name and arguments,
// one per line, ending the call with "---". It exits with $FAKE_RC, except
// that "--fail-on none" always exits 0; unless it exits 2 it writes "{}" to
// the --out file. As docker, an --out path inside a -v mount is written on
// the host side of that mount.
const fakeTool = `#!/bin/sh
{ basename "$0"; for a in "$@"; do printf '%s\n' "$a"; done; echo ---; } >> "$FAKE_LOG"
mounts=""; out=""; failon=""; prev=""
for a in "$@"; do
  case "$prev" in
    -v) mounts="$mounts $a" ;;
    --out) out="$a" ;;
    --fail-on) failon="$a" ;;
  esac
  prev="$a"
done
rc="${FAKE_RC:-0}"
[ "$failon" = none ] && rc=0
if [ -n "$out" ] && [ "$rc" -ne 2 ]; then
  target="$out"
  for m in $mounts; do
    host="${m%%:*}"; rest="${m#*:}"; ctr="${rest%%:*}"
    case "$out" in "$ctr"/*) target="$host${out#"$ctr"}" ;; esac
  done
  printf '{}\n' > "$target"
fi
exit "$rc"
`

// fakeWget logs like fakeTool and, unless $FAKE_WGET_RC is non-zero, writes
// an empty baseline report to the -O file.
const fakeWget = `#!/bin/sh
{ basename "$0"; for a in "$@"; do printf '%s\n' "$a"; done; echo ---; } >> "$FAKE_LOG"
out=""; prev=""
for a in "$@"; do [ "$prev" = -O ] && out="$a"; prev="$a"; done
rc="${FAKE_WGET_RC:-0}"
[ "$rc" -ne 0 ] && exit "$rc"
printf '{"schema_version":1,"findings":[]}\n' > "$out"
`

type call struct {
	tool string
	args []string
}

type scriptRun struct {
	code   int
	output string // stdout and stderr
	calls  []call
}

func (r scriptRun) of(tool string) []call {
	var out []call
	for _, c := range r.calls {
		if c.tool == tool {
			out = append(out, c)
		}
	}
	return out
}

// runScript runs script with shell in dir, with the fakes first on PATH and
// env added to a minimal environment (later keys win). It skips the test when
// the shell is not installed (bash is missing from golang:*-alpine).
func runScript(t *testing.T, shell, script, dir string, env map[string]string) scriptRun {
	t.Helper()
	if _, err := exec.LookPath(shell); err != nil {
		t.Skipf("%s not available: %v", shell, err)
	}
	bin := t.TempDir()
	for name, body := range map[string]string{"docker": fakeTool, "orbit": fakeTool, "wget": fakeWget} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logFile := filepath.Join(bin, "calls.log")
	cmd := exec.Command(shell, "-c", script)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + dir, "TMPDIR=" + t.TempDir(), "FAKE_LOG=" + logFile,
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	r := scriptRun{output: string(out)}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	case err != nil:
		t.Fatalf("run %s: %v", shell, err)
	}
	data, _ := os.ReadFile(logFile)
	var cur []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "---" {
			r.calls = append(r.calls, call{tool: cur[0], args: cur[1:]})
			cur = nil
			continue
		}
		if line != "" || cur != nil {
			cur = append(cur, line)
		}
	}
	return r
}

// hasSeq reports whether args contains seq as consecutive elements.
func hasSeq(args []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		if slices.Equal(args[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}

func loadYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

// ---- GitHub Action -------------------------------------------------------

func actionScript(t *testing.T) (inputs map[string]any, script string) {
	t.Helper()
	doc := loadYAML(t, "../action.yml")
	steps := doc["runs"].(map[string]any)["steps"].([]any)
	return doc["inputs"].(map[string]any), steps[0].(map[string]any)["run"].(string)
}

// actionEnv is the step's env as the runner sets it with every input at its
// default. The script runs under set -u, so each input must be present.
func actionEnv(ws string, extra map[string]string) map[string]string {
	env := map[string]string{
		"GITHUB_WORKSPACE": ws, "INPUT_PATH": ".", "INPUT_FAIL_ON": "high", "INPUT_FORMAT": "sarif",
		"INPUT_OUTPUT": "", "INPUT_IGNORE_FILE": "", "INPUT_VERSION": "v1.2.3", "ACTION_REF": "",
		"INPUT_FAIL_ON_KEV": "false", "INPUT_EXPLOIT_DATA": "true",
		"INPUT_BASELINE": "", "INPUT_BASELINE_OUTPUT": "",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func TestActionDeclaresBaselineInputs(t *testing.T) {
	inputs, _ := actionScript(t)
	for _, name := range []string{"baseline", "baseline-output"} {
		in, ok := inputs[name].(map[string]any)
		if !ok || in["default"] != "" || in["required"] != false {
			t.Errorf("input %s = %v, want optional with default \"\"", name, inputs[name])
		}
	}
}

func TestActionWithoutBaselineRunsOnce(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{"FAKE_RC": "1"}))
	if r.code != 1 || len(r.of("docker")) != 1 || slices.Contains(r.of("docker")[0].args, "--baseline") {
		t.Fatalf("exit %d, calls %+v; output:\n%s", r.code, r.calls, r.output)
	}
}

func TestActionPassesBaselineWhenTheFileExists(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "orbit-baseline.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, rc := range []int{0, 1} {
		r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{
			"INPUT_BASELINE": "orbit-baseline.json", "FAKE_RC": strconv.Itoa(rc),
		}))
		d := r.of("docker")
		if r.code != rc || len(d) != 1 || !hasSeq(d[0].args, "--baseline", "/src/orbit-baseline.json") {
			t.Fatalf("rc %d: exit %d, calls %+v; output:\n%s", rc, r.code, r.calls, r.output)
		}
	}
}

func TestActionWarnsWithoutBaselineFile(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{"INPUT_BASELINE": "orbit-baseline.json", "FAKE_RC": "1"}))
	d := r.of("docker")
	if r.code != 1 || len(d) != 1 || slices.Contains(d[0].args, "--baseline") {
		t.Fatalf("exit %d, calls %+v", r.code, r.calls)
	}
	if !strings.Contains(r.output, "::warning::Orbit: no baseline at 'orbit-baseline.json'") {
		t.Errorf("no warning:\n%s", r.output)
	}
}

// A run that records the baseline is not failed by its findings: on the
// recording branch every finding is an existing one. They are reported and
// the exit 1 becomes a warning.
func TestActionWritesBaselineOutput(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{"INPUT_BASELINE_OUTPUT": "orbit-baseline.json", "FAKE_RC": "1"}))
	d := r.of("docker")
	if r.code != 0 || len(d) != 2 {
		t.Fatalf("exit %d (want 0: the run records the baseline), %d docker calls (want 2); output:\n%s", r.code, len(d), r.output)
	}
	if !hasSeq(d[0].args, "--fail-on", "high", "--format", "sarif", "--out", "/src/orbit.sarif") {
		t.Errorf("first run = %v", d[0].args)
	}
	if !hasSeq(d[1].args, "--fail-on", "none", "--format", "json", "--out", "/src/orbit-baseline.json") || !slices.Contains(d[1].args, "--quiet") {
		t.Errorf("second run = %v", d[1].args)
	}
	if _, err := os.Stat(filepath.Join(ws, "orbit-baseline.json")); err != nil {
		t.Errorf("baseline not written: %v", err)
	}
	if !strings.Contains(r.output, "::warning::Orbit:") || !strings.Contains(r.output, "records the baseline") {
		t.Errorf("no warning about the findings:\n%s", r.output)
	}
}

func TestActionSkipsBaselineOutputAfterAnError(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{"INPUT_BASELINE_OUTPUT": "orbit-baseline.json", "FAKE_RC": "2"}))
	if r.code != 2 || len(r.of("docker")) != 1 {
		t.Fatalf("exit %d, calls %+v", r.code, r.calls)
	}
}

func TestActionSkipsBaselineOutputWhenTheReportIsIt(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{
		"INPUT_FORMAT": "json", "INPUT_OUTPUT": "orbit-baseline.json", "INPUT_BASELINE_OUTPUT": "orbit-baseline.json",
	}))
	if r.code != 0 || len(r.of("docker")) != 1 {
		t.Fatalf("exit %d, calls %+v", r.code, r.calls)
	}
}

// Plan 02's inputs: fail-on-kev gates only the first run; exploit-data false
// keeps every run, the baseline one too, from contacting cisa.gov and
// api.first.org.
func TestActionBaselineOutputKeepsExploitFlags(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{
		"INPUT_BASELINE_OUTPUT": "orbit-baseline.json", "INPUT_FAIL_ON_KEV": "true", "INPUT_EXPLOIT_DATA": "false",
	}))
	d := r.of("docker")
	if r.code != 0 || len(d) != 2 {
		t.Fatalf("exit %d, calls %+v; output:\n%s", r.code, r.calls, r.output)
	}
	if !slices.Contains(d[0].args, "--fail-on-kev") || !slices.Contains(d[0].args, "--no-exploit-data") {
		t.Errorf("first run = %v, want --fail-on-kev and --no-exploit-data", d[0].args)
	}
	if slices.Contains(d[1].args, "--fail-on-kev") || !slices.Contains(d[1].args, "--no-exploit-data") {
		t.Errorf("baseline run = %v, want --no-exploit-data and no --fail-on-kev", d[1].args)
	}
}

func TestActionDefaultsLeaveExploitFlagsOut(t *testing.T) {
	_, script := actionScript(t)
	ws := t.TempDir()
	r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{"INPUT_BASELINE_OUTPUT": "orbit-baseline.json"}))
	d := r.of("docker")
	if r.code != 0 || len(d) != 2 {
		t.Fatalf("exit %d, calls %+v; output:\n%s", r.code, r.calls, r.output)
	}
	for i, c := range d {
		if slices.Contains(c.args, "--fail-on-kev") || slices.Contains(c.args, "--no-exploit-data") {
			t.Errorf("run %d = %v, want neither --fail-on-kev nor --no-exploit-data", i, c.args)
		}
	}
}

func TestActionRejectsInvalidBooleans(t *testing.T) {
	_, script := actionScript(t)
	for key, val := range map[string]string{"INPUT_FAIL_ON_KEV": "yes", "INPUT_EXPLOIT_DATA": "no"} {
		ws := t.TempDir()
		r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{key: val, "INPUT_BASELINE_OUTPUT": "orbit-baseline.json"}))
		if r.code != 2 || len(r.calls) != 0 || !strings.Contains(r.output, "::error::Orbit:") {
			t.Errorf("%s=%s: exit %d, calls %+v; output:\n%s", key, val, r.code, r.calls, r.output)
		}
	}
}

func TestActionRejectsAbsolutePaths(t *testing.T) {
	_, script := actionScript(t)
	for _, key := range []string{"INPUT_PATH", "INPUT_BASELINE", "INPUT_BASELINE_OUTPUT"} {
		ws := t.TempDir()
		r := runScript(t, "bash", script, ws, actionEnv(ws, map[string]string{key: "/etc/passwd"}))
		if r.code != 2 || len(r.calls) != 0 || !strings.Contains(r.output, "::error::Orbit:") {
			t.Errorf("%s: exit %d, calls %+v; output:\n%s", key, r.code, r.calls, r.output)
		}
	}
}

func TestBaselineExampleWorkflowParses(t *testing.T) {
	doc := loadYAML(t, "../.github/examples/orbit-scan-baseline.yml")
	steps := doc["jobs"].(map[string]any)["orbit"].(map[string]any)["steps"].([]any)
	var uses []string
	for _, s := range steps {
		if u, ok := s.(map[string]any)["uses"].(string); ok {
			uses = append(uses, strings.SplitN(u, "@", 2)[0])
		}
	}
	want := []string{"actions/checkout", "actions/cache/restore", "orchesta/orbit", "actions/cache/save", "github/codeql-action/upload-sarif"}
	if !slices.Equal(uses, want) {
		t.Errorf("steps = %v, want %v", uses, want)
	}
}

// Third-party actions in the examples are pinned to a full commit SHA. The
// orbit action itself is left at a placeholder tag for users to pin.
func TestExampleWorkflowsPinActions(t *testing.T) {
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, path := range []string{"../.github/examples/orbit-scan.yml", "../.github/examples/orbit-scan-baseline.yml"} {
		for name, job := range loadYAML(t, path)["jobs"].(map[string]any) {
			for _, s := range job.(map[string]any)["steps"].([]any) {
				u, ok := s.(map[string]any)["uses"].(string)
				if !ok || strings.HasPrefix(u, "orchesta/orbit@") {
					continue
				}
				if _, ref, _ := strings.Cut(u, "@"); !sha.MatchString(ref) {
					t.Errorf("%s: job %s: %s is not pinned to a commit SHA", path, name, u)
				}
			}
		}
	}
}
