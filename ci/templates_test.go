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
// that "--fail-on none" always exits 0 and that, when $FAKE_RECORD_RC is set,
// a "--format json" run (the one that records the baseline) exits with it;
// unless it exits 2 it writes "{}" to the --out file. As docker, an --out
// path inside a -v mount is written on the host side of that mount.
const fakeTool = `#!/bin/sh
{ basename "$0"; for a in "$@"; do printf '%s\n' "$a"; done; echo ---; } >> "$FAKE_LOG"
mounts=""; out=""; failon=""; format=""; prev=""
for a in "$@"; do
  case "$prev" in
    -v) mounts="$mounts $a" ;;
    --out) out="$a" ;;
    --fail-on) failon="$a" ;;
    --format) format="$a" ;;
  esac
  prev="$a"
done
rc="${FAKE_RC:-0}"
[ "$failon" = none ] && rc=0
[ "$format" = json ] && [ -n "${FAKE_RECORD_RC:-}" ] && rc="$FAKE_RECORD_RC"
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

// ---- GitLab --------------------------------------------------------------

func gitlabJob(t *testing.T) map[string]any {
	t.Helper()
	return loadYAML(t, "gitlab/orbit.gitlab-ci.yml")[".orbit-scan"].(map[string]any)
}

// gitlabScript is the job's script as the runner runs it: with errexit on.
func gitlabScript(t *testing.T) string {
	t.Helper()
	return "set -e\n" + gitlabJob(t)["script"].([]any)[0].(string)
}

// gitlabEnv is the predefined CI/CD variables the script reads. The ORBIT_*
// variables are left unset: the template applies their defaults itself.
func gitlabEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		"CI_PROJECT_DIR": ".", "CI_API_V4_URL": "https://gitlab.example.com/api/v4", "CI_PROJECT_ID": "42",
		"CI_JOB_TOKEN": "job-token", "CI_JOB_NAME": "orbit-scan", "CI_DEFAULT_BRANCH": "main",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func TestGitLabKeepsTheBaselineArtifact(t *testing.T) {
	paths := gitlabJob(t)["artifacts"].(map[string]any)["paths"].([]any)
	if !slices.Contains(paths, any("orbit-baseline.json")) {
		t.Errorf("artifacts.paths = %v, want orbit-baseline.json", paths)
	}
}

func TestGitLabWithoutBaselineIsUnchanged(t *testing.T) {
	r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{"FAKE_RC": "1", "CI_COMMIT_BRANCH": "main"}))
	o := r.of("orbit")
	if r.code != 1 || len(o) != 2 || len(r.of("wget")) != 0 {
		t.Fatalf("exit %d, calls %+v; output:\n%s", r.code, r.calls, r.output)
	}
	for _, c := range o {
		if slices.Contains(c.args, "--baseline") {
			t.Errorf("unexpected --baseline: %v", c.args)
		}
	}
}

// The default branch records the baseline. Its findings are reported but do
// not fail the job: GitLab serves artifacts only from successful pipelines,
// so a failing job would never leave a baseline behind.
func TestGitLabAutoRecordsOnDefaultBranch(t *testing.T) {
	dir := t.TempDir()
	r := runScript(t, "sh", gitlabScript(t), dir, gitlabEnv(map[string]string{
		"ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "main", "FAKE_RC": "1",
	}))
	o := r.of("orbit")
	if r.code != 0 || len(o) != 3 || len(r.of("wget")) != 0 {
		t.Fatalf("exit %d (want 0: the default branch records), %d orbit calls (want 3); output:\n%s", r.code, len(o), r.output)
	}
	if !hasSeq(o[2].args, "--fail-on", "none") || !hasSeq(o[2].args, "--format", "json", "--out", "orbit-baseline.json") ||
		!slices.Contains(o[2].args, "--quiet") {
		t.Errorf("third run = %v", o[2].args)
	}
	for i, c := range o {
		if slices.Contains(c.args, "--baseline") {
			t.Errorf("run %d = %v, want no --baseline while recording", i, c.args)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "orbit-baseline.json")); err != nil {
		t.Errorf("orbit-baseline.json not written: %v", err)
	}
	if !strings.Contains(r.output, "records the baseline") {
		t.Errorf("no note about recording:\n%s", r.output)
	}
}

func TestGitLabAutoRecordingStillFailsOnErrors(t *testing.T) {
	r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
		"ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "main", "FAKE_RC": "2",
	}))
	if r.code != 2 || len(r.of("orbit")) != 1 {
		t.Fatalf("exit %d, calls %+v", r.code, r.calls)
	}
}

// A failed recording scan fails the job (exit 2), also when the findings
// alone would only have warned: a passing job without orbit-baseline.json
// would become the latest successful pipeline and leave every merge request
// without a baseline. A file left from before is removed, not kept.
func TestGitLabAutoRecordingFailsWhenTheBaselineScanFails(t *testing.T) {
	for _, rc := range []int{0, 1} {
		dir := t.TempDir()
		stale := filepath.Join(dir, "orbit-baseline.json")
		if err := os.WriteFile(stale, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := runScript(t, "sh", gitlabScript(t), dir, gitlabEnv(map[string]string{
			"ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "main", "FAKE_RC": strconv.Itoa(rc), "FAKE_RECORD_RC": "2",
		}))
		if r.code != 2 || len(r.of("orbit")) != 3 || !strings.Contains(r.output, "error: could not write orbit-baseline.json") {
			t.Fatalf("rc %d: exit %d (want 2), calls %+v; output:\n%s", rc, r.code, r.calls, r.output)
		}
		if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("rc %d: orbit-baseline.json left behind: %v", rc, err)
		}
	}
}

func TestGitLabAutoInMergeRequestDownloadsTheBaseline(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
		"ORBIT_BASELINE": "auto", "CI_MERGE_REQUEST_IID": "7", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "release/1.0",
		"CI_JOB_NAME": "orbit scan", "TMPDIR": tmp, "FAKE_RC": "1",
	}))
	w := r.of("wget")
	if len(w) != 1 {
		t.Fatalf("wget calls = %+v; output:\n%s", w, r.output)
	}
	if !hasSeq(w[0].args, "--header", "JOB-TOKEN: job-token") ||
		!slices.Contains(w[0].args, "https://gitlab.example.com/api/v4/projects/42/jobs/artifacts/release%2F1.0/raw/orbit-baseline.json?job=orbit%20scan") {
		t.Errorf("wget args = %v", w[0].args)
	}
	prev := filepath.Join(tmp, "orbit-baseline.prev.json")
	o := r.of("orbit")
	if r.code != 1 || len(o) != 2 {
		t.Fatalf("exit %d, %d orbit calls; output:\n%s", r.code, len(o), r.output)
	}
	for _, c := range o {
		if !hasSeq(c.args, "--baseline", prev) {
			t.Errorf("orbit call lacks --baseline %s: %v", prev, c.args)
		}
	}
}

// A branch pipeline outside the default branch downloads from the default
// branch; ORBIT_BASELINE_JOB names the recording job when it differs.
func TestGitLabAutoOnBranchUsesDefaultBranchAndBaselineJob(t *testing.T) {
	r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
		"ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "feature", "ORBIT_BASELINE_JOB": "scan:main",
	}))
	w := r.of("wget")
	if r.code != 0 || len(w) != 1 || len(r.of("orbit")) != 2 {
		t.Fatalf("exit %d, calls %+v; output:\n%s", r.code, r.calls, r.output)
	}
	if !slices.Contains(w[0].args, "https://gitlab.example.com/api/v4/projects/42/jobs/artifacts/main/raw/orbit-baseline.json?job=scan:main") {
		t.Errorf("wget args = %v", w[0].args)
	}
}

// With no baseline yet (a first run, or a target branch that never recorded
// one) the job warns and every finding counts; the download failure itself
// does not fail the job.
func TestGitLabAutoWithoutBaselineCountsEverything(t *testing.T) {
	for _, rc := range []int{0, 1} {
		tmp := t.TempDir()
		r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
			"ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "feature", "FAKE_WGET_RC": "1",
			"FAKE_RC": strconv.Itoa(rc), "TMPDIR": tmp,
		}))
		if r.code != rc || len(r.of("orbit")) != 2 ||
			!strings.Contains(r.output, "warning: no Orbit baseline from the latest successful main pipeline") {
			t.Fatalf("rc %d: exit %d, calls %+v; output:\n%s", rc, r.code, r.calls, r.output)
		}
		for _, c := range r.of("orbit") {
			if slices.Contains(c.args, "--baseline") {
				t.Errorf("--baseline without a baseline: %v", c.args)
			}
		}
		if _, err := os.Stat(filepath.Join(tmp, "orbit-baseline.prev.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("failed download left a file behind: %v", err)
		}
	}
}

func TestGitLabExplicitBaselinePath(t *testing.T) {
	r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
		"ORBIT_BASELINE": "ci/base line.json", "CI_COMMIT_BRANCH": "main",
	}))
	o := r.of("orbit")
	if r.code != 0 || len(o) != 2 || len(r.of("wget")) != 0 {
		t.Fatalf("exit %d, calls %+v (an explicit path neither downloads nor records); output:\n%s", r.code, r.calls, r.output)
	}
	for _, c := range o {
		if !hasSeq(c.args, "--baseline", "ci/base line.json") {
			t.Errorf("orbit call lacks the explicit baseline: %v", c.args)
		}
	}
}

// Plan 02's variables: ORBIT_FAIL_ON_KEV gates only the first run;
// ORBIT_EXPLOIT_DATA false keeps every run, the recording one too, from
// contacting cisa.gov and api.first.org.
func TestGitLabBaselineKeepsExploitFlags(t *testing.T) {
	r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
		"ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "main", "ORBIT_FAIL_ON_KEV": "true", "ORBIT_EXPLOIT_DATA": "false",
	}))
	o := r.of("orbit")
	if r.code != 0 || len(o) != 3 {
		t.Fatalf("exit %d, calls %+v; output:\n%s", r.code, r.calls, r.output)
	}
	if !slices.Contains(o[0].args, "--fail-on-kev") || !slices.Contains(o[0].args, "--no-exploit-data") {
		t.Errorf("first run = %v, want --fail-on-kev and --no-exploit-data", o[0].args)
	}
	for i, c := range o[1:] {
		if slices.Contains(c.args, "--fail-on-kev") || !slices.Contains(c.args, "--no-exploit-data") {
			t.Errorf("run %d = %v, want --no-exploit-data and no --fail-on-kev", i+2, c.args)
		}
	}
}

func TestGitLabDefaultsLeaveExploitFlagsOut(t *testing.T) {
	r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
		"ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "main",
	}))
	o := r.of("orbit")
	if r.code != 0 || len(o) != 3 {
		t.Fatalf("exit %d, calls %+v; output:\n%s", r.code, r.calls, r.output)
	}
	for i, c := range o {
		if slices.Contains(c.args, "--fail-on-kev") || slices.Contains(c.args, "--no-exploit-data") {
			t.Errorf("run %d = %v, want neither --fail-on-kev nor --no-exploit-data", i+1, c.args)
		}
	}
}

func TestGitLabRejectsInvalidBooleans(t *testing.T) {
	for key, val := range map[string]string{"ORBIT_FAIL_ON_KEV": "yes", "ORBIT_EXPLOIT_DATA": "no"} {
		r := runScript(t, "sh", gitlabScript(t), t.TempDir(), gitlabEnv(map[string]string{
			key: val, "ORBIT_BASELINE": "auto", "CI_COMMIT_BRANCH": "feature",
		}))
		if r.code != 2 || len(r.calls) != 0 || !strings.Contains(r.output, "error: "+key) {
			t.Errorf("%s=%s: exit %d, calls %+v; output:\n%s", key, val, r.code, r.calls, r.output)
		}
	}
}

// ---- Azure Pipelines -----------------------------------------------------

// azureSteps returns every step of the Azure template, also those inside
// ${{ if }} blocks, in file order (each conditional block has one key).
func azureSteps(t *testing.T) []map[string]any {
	t.Helper()
	doc := loadYAML(t, "azure-pipelines/orbit-scan.yml")
	var out []map[string]any
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, k := range []string{"bash", "powershell", "task"} {
				if _, ok := x[k]; ok {
					out = append(out, x)
					return
				}
			}
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc["steps"])
	return out
}

func azureScanScript(t *testing.T, marker string) string {
	t.Helper()
	for _, s := range azureSteps(t) {
		if b, ok := s["bash"].(string); ok && s["displayName"] == "Orbit scan" && strings.Contains(b, marker) {
			return b
		}
	}
	t.Fatalf("no Orbit scan bash step containing %q", marker)
	return ""
}

// azureEnv is the env of an "Orbit scan" step with every parameter at its
// default: the template sets the ORBIT_* switches to empty strings when they
// are off.
func azureEnv(tmp string, extra map[string]string) map[string]string {
	env := map[string]string{
		"ORBIT_PATH": tmp, "ORBIT_FAIL_ON": "high", "ORBIT_IGNORE_FILE": "", "ORBIT_VERSION": "v1.0.0",
		"ORBIT_IMAGE": "orchestalabs/orbit-cli", "AGENT_TEMPDIRECTORY": tmp, "BUILD_SOURCEBRANCH": "refs/pull/1/merge",
		"ORBIT_FAIL_ON_KEV": "", "ORBIT_NO_EXPLOIT_DATA": "", "ORBIT_BASELINE_BRANCH": "",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// writeAzureBaseline puts a baseline where the download step leaves it.
func writeAzureBaseline(t *testing.T, tmp string) string {
	t.Helper()
	base := filepath.Join(tmp, "orbit-baseline", "orbit-baseline.json")
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestAzureTemplateBaselineSteps(t *testing.T) {
	params := map[string]map[string]any{}
	for _, p := range loadYAML(t, "azure-pipelines/orbit-scan.yml")["parameters"].([]any) {
		m := p.(map[string]any)
		params[m["name"].(string)] = m
	}
	if p := params["baseline"]; p == nil || p["type"] != "boolean" || p["default"] != false {
		t.Errorf("parameter baseline = %v", p)
	}
	if p := params["baselineBranch"]; p == nil || p["type"] != "string" || p["default"] != "refs/heads/main" {
		t.Errorf("parameter baselineBranch = %v", p)
	}
	var download, publish map[string]any
	scans := 0
	for _, s := range azureSteps(t) {
		in, _ := s["inputs"].(map[string]any)
		switch s["task"] {
		case "DownloadBuildArtifacts@0":
			download = s
		case "PublishBuildArtifacts@1":
			if in["ArtifactName"] == "orbit-baseline" {
				publish = s
			}
		}
		if s["displayName"] == "Orbit scan" {
			scans++
			env := s["env"].(map[string]any)
			on, _ := env["${{ if eq(parameters.baseline, true) }}"].(map[string]any)
			if on["ORBIT_BASELINE_BRANCH"] != "${{ parameters.baselineBranch }}" {
				t.Errorf("%v step does not pass ORBIT_BASELINE_BRANCH in baseline mode", s["condition"])
			}
			// Set to '' when off, so a pipeline variable of that name cannot
			// turn on recording (which turns exit 1 into 0).
			off, _ := env["${{ if eq(parameters.baseline, false) }}"].(map[string]any)
			if v, ok := off["ORBIT_BASELINE_BRANCH"]; !ok || v != "" {
				t.Errorf("%v step does not clear ORBIT_BASELINE_BRANCH without baseline mode", s["condition"])
			}
		}
	}
	if scans != 3 {
		t.Errorf("%d Orbit scan steps, want 3 (container, binary bash, PowerShell)", scans)
	}
	if download == nil || publish == nil {
		t.Fatalf("download %v, publish %v", download, publish)
	}
	in := download["inputs"].(map[string]any)
	want := map[string]any{
		"buildType": "specific", "project": "$(System.TeamProjectId)", "pipeline": "$(System.DefinitionId)",
		"buildVersionToDownload": "latestFromBranch", "branchName": "${{ parameters.baselineBranch }}",
		"allowPartiallySucceededBuilds": true, "downloadType": "single", "artifactName": "orbit-baseline",
		"downloadPath": "$(Agent.TempDirectory)",
	}
	for k, v := range want {
		if in[k] != v {
			t.Errorf("download input %s = %v, want %v", k, in[k], v)
		}
	}
	if download["continueOnError"] != true {
		t.Error("a missing baseline must not fail the build")
	}
	// not(canceled()) like the scan steps, whose conditions have no status
	// function: they run after a failed earlier step, so the download must too.
	if c, _ := download["condition"].(string); c != "and(not(canceled()), ne(variables['Build.SourceBranch'], '${{ parameters.baselineBranch }}'))" {
		t.Errorf("download condition = %q, want it skipped on the baseline branch and when canceled only", c)
	}
	pin := publish["inputs"].(map[string]any)
	if pin["PathtoPublish"] != "$(ORBIT_REPORTS)/orbit-baseline.json" ||
		publish["condition"] != "and(always(), eq(variables['ORBIT_HAS_BASELINE'], 'true'))" {
		t.Errorf("publish step = %v", publish)
	}
}

func TestAzureContainerRecordsOnBaselineBranch(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureScanScript(t, "docker run"), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "BUILD_SOURCEBRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	d := r.of("docker")
	if len(d) != 3 || !hasSeq(d[2].args, "--fail-on", "none") || !hasSeq(d[2].args, "--format", "json", "--out", "/out/orbit-baseline.json") {
		t.Fatalf("docker calls %+v; output:\n%s", d, r.output)
	}
	for i, c := range d {
		if slices.Contains(c.args, "--baseline") {
			t.Errorf("run %d = %v, want no --baseline while recording", i+1, c.args)
		}
	}
	if _, err := os.Stat(filepath.Join(tmp, "orbit-reports", "orbit-baseline.json")); err != nil {
		t.Errorf("orbit-baseline.json not written: %v", err)
	}
	for _, want := range []string{"variable=ORBIT_EXIT]0", "variable=ORBIT_HAS_BASELINE]true", "records the baseline"} {
		if !strings.Contains(r.output, want) {
			t.Errorf("output lacks %q:\n%s", want, r.output)
		}
	}
}

// Azure compares strings ignoring case, so the download step treats
// refs/heads/Main as the baseline branch; the script must agree.
func TestAzureContainerMatchesTheBranchIgnoringCase(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureScanScript(t, "docker run"), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/Main", "BUILD_SOURCEBRANCH": "refs/heads/main",
	}))
	if len(r.of("docker")) != 3 || !strings.Contains(r.output, "variable=ORBIT_HAS_BASELINE]true") {
		t.Fatalf("calls %+v; output:\n%s", r.calls, r.output)
	}
}

func TestAzureContainerRecordingStillFailsOnErrors(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureScanScript(t, "docker run"), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "BUILD_SOURCEBRANCH": "refs/heads/main", "FAKE_RC": "2",
	}))
	if len(r.of("docker")) != 1 || !strings.Contains(r.output, "variable=ORBIT_EXIT]2") ||
		strings.Contains(r.output, "ORBIT_HAS_BASELINE") {
		t.Fatalf("calls %+v; output:\n%s", r.calls, r.output)
	}
}

// A failed recording scan fails the build (exit 2) and publishes no
// baseline, so the download keeps taking the previous good build's. A file
// left from before is removed, not published.
func azureRecordFailure(t *testing.T, script, tool string) {
	t.Helper()
	for _, rc := range []int{0, 1} {
		tmp := t.TempDir()
		stale := filepath.Join(tmp, "orbit-reports", "orbit-baseline.json")
		if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stale, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := runScript(t, "bash", script, tmp, azureEnv(tmp, map[string]string{
			"ORBIT_BASELINE_BRANCH": "refs/heads/main", "BUILD_SOURCEBRANCH": "refs/heads/main",
			"FAKE_RC": strconv.Itoa(rc), "FAKE_RECORD_RC": "2",
		}))
		if len(r.of(tool)) != 3 || !strings.Contains(r.output, "variable=ORBIT_EXIT]2") ||
			!strings.Contains(r.output, "type=error]Orbit: could not write orbit-baseline.json") ||
			strings.Contains(r.output, "ORBIT_HAS_BASELINE") {
			t.Fatalf("rc %d: calls %+v; output:\n%s", rc, r.calls, r.output)
		}
		if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("rc %d: orbit-baseline.json left behind: %v", rc, err)
		}
	}
}

func TestAzureContainerRecordingFailsWhenTheBaselineScanFails(t *testing.T) {
	azureRecordFailure(t, azureScanScript(t, "docker run"), "docker")
}

func TestAzureContainerComparesWithTheBaseline(t *testing.T) {
	tmp := t.TempDir()
	writeAzureBaseline(t, tmp)
	r := runScript(t, "bash", azureScanScript(t, "docker run"), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	d := r.of("docker")
	if len(d) != 2 || !strings.Contains(r.output, "variable=ORBIT_EXIT]1") || strings.Contains(r.output, "ORBIT_HAS_BASELINE") {
		t.Fatalf("docker calls %+v; output:\n%s", d, r.output)
	}
	for _, c := range d {
		if !hasSeq(c.args, "--baseline", "/baseline/orbit-baseline.json") ||
			!hasSeq(c.args, "-v", filepath.Join(tmp, "orbit-baseline")+":/baseline:ro") {
			t.Errorf("call lacks --baseline or its mount: %v", c.args)
		}
	}
}

func TestAzureContainerWarnsWithoutBaseline(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureScanScript(t, "docker run"), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	if !strings.Contains(r.output, "##vso[task.logissue type=warning]Orbit: no baseline was downloaded from refs/heads/main;") ||
		!strings.Contains(r.output, "variable=ORBIT_EXIT]1") {
		t.Fatalf("output:\n%s", r.output)
	}
	for _, c := range r.of("docker") {
		if slices.Contains(c.args, "--baseline") {
			t.Errorf("--baseline without a baseline: %v", c.args)
		}
	}
}

func TestAzureContainerWithoutBaselineModeIsUnchanged(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureScanScript(t, "docker run"), tmp, azureEnv(tmp, map[string]string{
		"BUILD_SOURCEBRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	if len(r.of("docker")) != 2 || !strings.Contains(r.output, "variable=ORBIT_EXIT]1") || strings.Contains(r.output, "baseline") {
		t.Fatalf("calls %+v; output:\n%s", r.calls, r.output)
	}
	for _, c := range r.of("docker") {
		if strings.Contains(strings.Join(c.args, " "), "baseline") {
			t.Errorf("baseline in a call without baseline mode: %v", c.args)
		}
	}
}

// Plan 02's switches: ORBIT_FAIL_ON_KEV gates only the first run;
// ORBIT_NO_EXPLOIT_DATA reaches every run, the recording one too. The ignore
// file applies to every run.
func TestAzureContainerBaselineKeepsExploitFlags(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureScanScript(t, "docker run"), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "BUILD_SOURCEBRANCH": "refs/heads/main",
		"ORBIT_FAIL_ON_KEV": "true", "ORBIT_NO_EXPLOIT_DATA": "true", "ORBIT_IGNORE_FILE": ".orbitignore",
	}))
	d := r.of("docker")
	if len(d) != 3 {
		t.Fatalf("calls %+v; output:\n%s", r.calls, r.output)
	}
	if !slices.Contains(d[0].args, "--fail-on-kev") {
		t.Errorf("first run = %v, want --fail-on-kev", d[0].args)
	}
	for i, c := range d {
		if !slices.Contains(c.args, "--no-exploit-data") || !hasSeq(c.args, "--ignore-file", "/src/.orbitignore") {
			t.Errorf("run %d = %v, want --no-exploit-data and the ignore file", i+1, c.args)
		}
		if i > 0 && slices.Contains(c.args, "--fail-on-kev") {
			t.Errorf("run %d = %v, want no --fail-on-kev", i+1, c.args)
		}
	}
}

// The binary-mode script with its download section replaced by the fake orbit.
func azureBinaryScript(t *testing.T) string {
	t.Helper()
	s := azureScanScript(t, "# --- download-begin")
	begin, end := strings.Index(s, "# --- download-begin"), strings.Index(s, "# --- download-end")
	return s[:begin] + "orbit=\"$(command -v orbit)\"\n" + s[end:]
}

func TestAzureBinaryRecordsAndCompares(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureBinaryScript(t), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "BUILD_SOURCEBRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	o := r.of("orbit")
	if len(o) != 3 || !hasSeq(o[2].args, "--out", filepath.Join(tmp, "orbit-reports", "orbit-baseline.json")) ||
		!strings.Contains(r.output, "variable=ORBIT_EXIT]0") || !strings.Contains(r.output, "variable=ORBIT_HAS_BASELINE]true") {
		t.Fatalf("record: calls %+v; output:\n%s", o, r.output)
	}

	tmp = t.TempDir()
	base := writeAzureBaseline(t, tmp)
	r = runScript(t, "bash", azureBinaryScript(t), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	o = r.of("orbit")
	if len(o) != 2 || !strings.Contains(r.output, "variable=ORBIT_EXIT]1") {
		t.Fatalf("compare: calls %+v; output:\n%s", o, r.output)
	}
	for _, c := range o {
		if !hasSeq(c.args, "--baseline", base) {
			t.Errorf("compare: call lacks --baseline: %v", c.args)
		}
	}
}

func TestAzureBinaryWarnsWithoutBaseline(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureBinaryScript(t), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	o := r.of("orbit")
	if len(o) != 2 || !strings.Contains(r.output, "type=warning]Orbit: no baseline was downloaded from refs/heads/main;") ||
		!strings.Contains(r.output, "variable=ORBIT_EXIT]1") {
		t.Fatalf("calls %+v; output:\n%s", o, r.output)
	}
	for _, c := range o {
		if slices.Contains(c.args, "--baseline") {
			t.Errorf("--baseline without a baseline: %v", c.args)
		}
	}
}

func TestAzureBinaryWithoutBaselineModeIsUnchanged(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureBinaryScript(t), tmp, azureEnv(tmp, map[string]string{
		"BUILD_SOURCEBRANCH": "refs/heads/main", "FAKE_RC": "1",
	}))
	o := r.of("orbit")
	if len(o) != 2 || !strings.Contains(r.output, "variable=ORBIT_EXIT]1") || strings.Contains(r.output, "baseline") {
		t.Fatalf("calls %+v; output:\n%s", o, r.output)
	}
}

func TestAzureBinaryRecordingStillFailsOnErrors(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureBinaryScript(t), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "BUILD_SOURCEBRANCH": "refs/heads/main", "FAKE_RC": "2",
	}))
	if len(r.of("orbit")) != 1 || !strings.Contains(r.output, "variable=ORBIT_EXIT]2") {
		t.Fatalf("calls %+v; output:\n%s", r.calls, r.output)
	}
}

func TestAzureBinaryRecordingFailsWhenTheBaselineScanFails(t *testing.T) {
	azureRecordFailure(t, azureBinaryScript(t), "orbit")
}

func TestAzureBinaryBaselineKeepsExploitFlags(t *testing.T) {
	tmp := t.TempDir()
	r := runScript(t, "bash", azureBinaryScript(t), tmp, azureEnv(tmp, map[string]string{
		"ORBIT_BASELINE_BRANCH": "refs/heads/main", "BUILD_SOURCEBRANCH": "refs/heads/main",
		"ORBIT_FAIL_ON_KEV": "true", "ORBIT_NO_EXPLOIT_DATA": "true", "ORBIT_IGNORE_FILE": ".orbitignore",
	}))
	o := r.of("orbit")
	if len(o) != 3 {
		t.Fatalf("calls %+v; output:\n%s", r.calls, r.output)
	}
	if !slices.Contains(o[0].args, "--fail-on-kev") {
		t.Errorf("first run = %v, want --fail-on-kev", o[0].args)
	}
	for i, c := range o {
		if !slices.Contains(c.args, "--no-exploit-data") || !hasSeq(c.args, "--ignore-file", filepath.Join(tmp, ".orbitignore")) {
			t.Errorf("run %d = %v, want --no-exploit-data and the ignore file", i+1, c.args)
		}
		if i > 0 && slices.Contains(c.args, "--fail-on-kev") {
			t.Errorf("run %d = %v, want no --fail-on-kev", i+1, c.args)
		}
	}
}

func TestAzureExampleSchedulesTheBaselineBranch(t *testing.T) {
	doc := loadYAML(t, "azure-pipelines/example.yml")
	sched, _ := doc["schedules"].([]any)
	if len(sched) != 1 {
		t.Fatalf("schedules = %v", doc["schedules"])
	}
	s := sched[0].(map[string]any)
	inc, _ := s["branches"].(map[string]any)["include"].([]any)
	if s["always"] != true || !slices.Equal(inc, []any{"main"}) {
		t.Errorf("schedule = %v, want main, always", s)
	}
	for _, st := range doc["steps"].([]any) {
		m := st.(map[string]any)
		if m["template"] == "orbit-scan.yml" {
			p := m["parameters"].(map[string]any)
			if p["baseline"] != true || p["baselineBranch"] != "refs/heads/main" {
				t.Errorf("template parameters = %v", p)
			}
			return
		}
	}
	t.Error("example does not use orbit-scan.yml")
}
