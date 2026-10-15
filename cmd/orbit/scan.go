package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/orchesta/orbit/internal/buildinfo"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
	"github.com/orchesta/orbit/internal/infrastructure/git"
	"github.com/orchesta/orbit/internal/infrastructure/vulnerability/osv"
	"github.com/orchesta/orbit/internal/report"
	vulnuc "github.com/orchesta/orbit/internal/usecase/vulnerability"
)

// Exit codes of orbit scan.
const (
	exitOK = 0 // no finding gates (see exitFailed)
	// exitFailed: a non-ignored finding gates (report.gates: it trips
	// report.failsGate, that is the threshold, a malicious package, or KEV
	// with --fail-on-kev, and with --baseline it is new or malicious).
	exitFailed = 1
	// exitError: the scan could not be completed or the flags are wrong, or
	// --fail-on-kev without the KEV catalog, or a missing or invalid
	// --baseline.
	exitError = 2
)

const ignoreFileName = ".orbitignore"

// analyzerEngine is the part of engine.Engine the scan command uses.
type analyzerEngine interface {
	Analyze(ctx context.Context, root string) (*engine.Result, error)
}

// engineConfig is what the command line decides about the engine.
type engineConfig struct {
	checkLatest bool // --outdated
	exploitData bool // not --no-exploit-data
}

// scanDeps holds what runScan needs from the outside world, so tests can
// replace the engine and the clock.
type scanDeps struct {
	newEngine func(ec engineConfig, logger *slog.Logger) analyzerEngine
	now       func() time.Time
}

// defaultScanDeps builds the production engine: all analyzers, a real
// osv.dev lookup and, unless turned off, CISA KEV and FIRST EPSS data. It
// needs no configuration, database or secrets.
func defaultScanDeps() scanDeps {
	return scanDeps{
		newEngine: func(ec engineConfig, logger *slog.Logger) analyzerEngine {
			osvClient := osv.NewClient()
			osvClient.Logger = logger
			return engine.New(newAnalyzerRegistry(), vulnuc.NewLookup(osvClient, logger), cliEngineOptions(ec, logger))
		},
		now: time.Now,
	}
}

// cliEngineOptions is how orbit scan runs the engine. Unlike the server it
// computes Via, which the reports show.
func cliEngineOptions(ec engineConfig, logger *slog.Logger) engine.Options {
	opts := engine.Options{CheckLatest: ec.checkLatest, Logger: logger}
	if ec.exploitData {
		opts.Exploit = exploit.NewEnricher(exploit.Config{Logger: logger})
	}
	return opts
}

// failOnLevels maps --fail-on values to report thresholds; "none" is "".
var failOnLevels = map[string]entity.Severity{
	"critical": entity.SeverityCritical,
	"high":     entity.SeverityHigh,
	"medium":   entity.SeverityMedium,
	"low":      entity.SeverityLow,
	"unknown":  entity.SeverityUnknown,
	"none":     "",
}

var scanFormats = []string{"table", "json", "sarif", "junit"}

// scanConfig is the validated command line of orbit scan.
type scanConfig struct {
	path       string
	threshold  entity.Severity
	failOn     string
	format     string
	out        string
	ignoreFile string
	ignoreSet  bool   // --ignore-file was given explicitly
	baseline   string // --baseline: earlier JSON report; "" compares with nothing
	outdated   bool
	timeout    time.Duration
	quiet      bool
	verbose    bool

	failOnKEV     bool // --fail-on-kev
	noExploitData bool // --no-exploit-data
}

// usageError is a problem with the command line.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func parseScanFlags(args []string, stderr io.Writer) (scanConfig, error) {
	var c scanConfig
	flags := flag.NewFlagSet("orbit scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&c.path, "path", ".", "directory to scan")
	flags.StringVar(&c.failOn, "fail-on", "high", "exit 1 on a finding at or above: critical|high|medium|low|unknown|none (a known malicious package fails at every threshold except none)")
	flags.StringVar(&c.format, "format", "table", "report format: "+strings.Join(scanFormats, "|"))
	flags.StringVar(&c.out, "out", "-", `report file, or "-" for stdout`)
	flags.StringVar(&c.ignoreFile, "ignore-file", "", "ignore file (default <path>/"+ignoreFileName+" if it exists)")
	flags.StringVar(&c.baseline, "baseline", "", "earlier orbit JSON report; only findings not in it fail the scan (malicious packages always do)")
	flags.BoolVar(&c.outdated, "outdated", false, "also ask the package registries for the latest versions")
	flags.BoolVar(&c.failOnKEV, "fail-on-kev", false, "also exit 1 on any finding in the CISA KEV catalog, whatever its severity")
	flags.BoolVar(&c.noExploitData, "no-exploit-data", false, "do not download the CISA KEV catalog or send CVE IDs to api.first.org for EPSS scores")
	flags.DurationVar(&c.timeout, "timeout", 10*time.Minute, "give up after this long")
	flags.BoolVar(&c.quiet, "quiet", false, "write only the summary and warnings to stderr")
	flags.BoolVar(&c.verbose, "verbose", false, "log progress details to stderr")
	if err := flags.Parse(args); err != nil {
		return c, err
	}
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "ignore-file" {
			c.ignoreSet = true
		}
	})

	if flags.NArg() > 0 {
		return c, usageError{fmt.Sprintf("unexpected argument %q", flags.Arg(0))}
	}
	threshold, ok := failOnLevels[strings.ToLower(c.failOn)]
	if !ok {
		return c, usageError{fmt.Sprintf("invalid --fail-on %q: want critical, high, medium, low, unknown or none", c.failOn)}
	}
	c.threshold = threshold
	c.format = strings.ToLower(c.format)
	if !slices.Contains(scanFormats, c.format) {
		return c, usageError{fmt.Sprintf("invalid --format %q: want %s", c.format, strings.Join(scanFormats, ", "))}
	}
	if c.timeout <= 0 {
		return c, usageError{fmt.Sprintf("invalid --timeout %s: must be positive", c.timeout)}
	}
	if c.out == "" {
		return c, usageError{`--out needs a file path or "-"`}
	}
	// A failed run removes --out (removeStaleReport), which would delete
	// the baseline itself.
	if c.baseline != "" && c.out != "-" && sameFile(c.baseline, c.out) {
		return c, usageError{"--out and --baseline name the same file; write the new report to another path"}
	}
	if c.failOnKEV && c.noExploitData {
		return c, usageError{"--fail-on-kev needs exploit data; it cannot be combined with --no-exploit-data"}
	}
	return c, nil
}

// runScan implements orbit scan and returns its exit code. stdout receives
// only the report, and only when the scan succeeded; everything else goes
// to stderr. Everything on stderr, and a table report on stdout or in the
// --out file, passes through a ciLogWriter, so repository text cannot run
// CI log commands.
func runScan(ctx context.Context, args []string, stdout, stderr io.Writer, deps scanDeps) int {
	safeErr := newCILogWriter(stderr)
	code := runScanSafe(ctx, args, stdout, safeErr, deps)
	_ = safeErr.Flush()
	return code
}

// runScanSafe is runScan with stderr already neutralised. It exits 1 when
// a finding gates (threshold, malicious package, or KEV with --fail-on-kev;
// with --baseline only new findings, and malicious ones, count) and 2 when
// the scan fails after the flags were accepted, including --fail-on-kev
// without the KEV catalog and a bad --baseline; then any --out file is
// removed so no stale report survives.
func runScanSafe(ctx context.Context, args []string, stdout, stderr io.Writer, deps scanDeps) int {
	cfg, err := parseScanFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "orbit scan: %v\n", err)
		} // the flag package has already printed its own parse errors
		// --out is left alone: with a mistyped command line it may name any
		// file ("orbit scan --out main.go --nope"), not a report.
		return exitError
	}
	failed, err := executeScan(ctx, cfg, stdout, stderr, deps)
	if err != nil {
		fmt.Fprintf(stderr, "orbit scan: %v\n", err)
		removeStaleReport(cfg.out, stderr)
		return exitError
	}
	if failed {
		return exitFailed
	}
	return exitOK
}

// executeScan runs the analysis, writes the report and the stderr summary, and
// reports whether a finding tripped the gate. Every error except a
// failing stdout itself happens before anything is written to stdout.
func executeScan(ctx context.Context, cfg scanConfig, stdout, stderr io.Writer, deps scanDeps) (failed bool, err error) {
	// The engine does not follow symlinks, so a symlinked --path (a common
	// CI checkout layout) is resolved first.
	root, err := filepath.EvalSymlinks(cfg.path)
	if err == nil {
		root, err = filepath.Abs(root)
	}
	if err != nil {
		return false, fmt.Errorf("invalid --path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return false, fmt.Errorf("invalid --path: %w", err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("invalid --path %s: not a directory", cfg.path)
	}
	ignores, err := loadIgnores(cfg, root)
	if err != nil {
		return false, err
	}
	baseline, err := loadBaseline(cfg.baseline)
	if err != nil {
		return false, err
	}

	level := slog.LevelWarn
	if cfg.verbose {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	if !cfg.quiet {
		fmt.Fprintf(stderr, "orbit: scanning %s\n", cfg.path)
		if baseline != nil {
			from := ""
			if baseline.ToolVersion != "" {
				from = ", written by orbit " + baseline.ToolVersion
			}
			fmt.Fprintf(stderr, "orbit: comparing with baseline %s (%d findings%s)\n", cfg.baseline, baseline.Len(), from)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	res, err := deps.newEngine(engineConfig{checkLatest: cfg.outdated, exploitData: !cfg.noExploitData}, logger).Analyze(ctx, root)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, fmt.Errorf("scan did not finish within --timeout %s: %w", cfg.timeout, err)
		}
		return false, fmt.Errorf("scan failed: %w", err)
	}
	if res == nil {
		return false, errors.New("scan failed: engine returned no result")
	}
	if cfg.failOnKEV {
		if err := kevAvailable(res); err != nil {
			return false, err
		}
	}

	findings, summary := report.BuildWithOptions(res, ignores,
		report.BuildOptions{Threshold: cfg.threshold, FailOnKEV: cfg.failOnKEV}, deps.now())
	report.ApplyBaseline(findings, &summary, baseline)

	if cfg.out == "-" {
		if err := writeStdout(stdout, cfg.format, findings, summary, sarifOptions(root)); err != nil {
			return false, fmt.Errorf("write report to stdout: %w", err)
		}
	} else {
		var buf bytes.Buffer
		if err := writeSafeReport(&buf, cfg.format, findings, summary, false, sarifOptions(root)); err != nil {
			return false, fmt.Errorf("render %s report: %w", cfg.format, err)
		}
		if err := replaceFile(cfg.out, buf.Bytes()); err != nil {
			return false, fmt.Errorf("write report: %w", err)
		}
		if !cfg.quiet {
			fmt.Fprintf(stderr, "orbit: wrote %s report to %s\n", cfg.format, cfg.out)
		}
	}

	// A table on stdout already ends with the counts, the threshold verdict
	// and the warnings; repeating them on stderr would show them twice.
	if cfg.out != "-" || cfg.format != "table" {
		writeSummary(stderr, summary)
	}
	return summary.Failed, nil
}

// kevAvailable stops --fail-on-kev when the KEV catalog could not be read:
// the gate the user asked for cannot be checked, and passing it would read
// as "nothing is known exploited". EPSS has no gate, so its failure stays
// a warning.
func kevAvailable(res *engine.Result) error {
	switch {
	case res.Exploit == nil:
		return errors.New("--fail-on-kev: no exploit data was collected")
	case res.Exploit.KEV.Status == exploit.StatusFailed:
		return fmt.Errorf("--fail-on-kev: %w", res.Exploit.KEV.Err)
	}
	return nil
}

// replaceFile writes data to a temporary file next to path and renames it
// onto path, so readers never see a partly written report. The file keeps
// the permissions of the one it replaces; a new file gets 0644. The
// temporary file is removed on any error.
func replaceFile(path string, data []byte) (err error) {
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".orbit-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// removeStaleReport deletes the --out file after a run with valid flags
// failed, so a CI step that uploads it regardless of the outcome cannot pick
// up a report from an earlier, possibly clean, run. Only a regular file is
// removed.
func removeStaleReport(out string, stderr io.Writer) {
	if out == "" || out == "-" {
		return
	}
	info, err := os.Lstat(out)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if err := os.Remove(out); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "orbit scan: could not remove the stale report %s: %v\n", out, err)
	}
}

// maxIgnoreFileBytes caps the size of an ignore file.
const maxIgnoreFileBytes = 1 << 20

// loadIgnores reads --ignore-file, or root/.orbitignore when the flag is not
// given and that file exists; root is the resolved --path. The default file
// must be a regular file inside root (a symlink is refused, so a repository
// cannot point the scan at a file elsewhere). An explicitly named file may be
// a symlink but must lead to a regular file. Both are capped at 1 MiB.
// --ignore-file "" disables ignores.
func loadIgnores(cfg scanConfig, root string) (*report.IgnoreList, error) {
	var (
		name string
		data []byte
		err  error
	)
	switch {
	case !cfg.ignoreSet:
		name = filepath.Join(cfg.path, ignoreFileName)
		data, err = git.NewLocalGit().ReadFileLimit(root, ignoreFileName, maxIgnoreFileBytes)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
	case cfg.ignoreFile == "":
		return nil, nil
	default:
		name = cfg.ignoreFile
		data, err = readRegularFile(cfg.ignoreFile, maxIgnoreFileBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("ignore file: %w", err)
	}
	list, err := report.ParseIgnoreFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("ignore file %s: %w", name, err)
	}
	return list, nil
}

// maxBaselineBytes caps the size of a baseline report.
const maxBaselineBytes = 64 << 20

// loadBaseline reads and parses --baseline before the scan starts, so a bad
// baseline fails fast (exit 2) without a network round trip. "" means no
// baseline. A missing file is an error, like a missing --ignore-file: the CI
// templates check for the file themselves and leave the flag out on a first
// run. Like an explicit --ignore-file, it may be a symlink but must lead to a
// regular file, so a directory or a FIFO is refused without blocking.
func loadBaseline(path string) (*report.Baseline, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readRegularFile(path, maxBaselineBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("baseline %s does not exist; on a first run there is no baseline yet, so leave out --baseline", path)
	}
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	b, err := report.ParseBaseline(data)
	if err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return b, nil
}

// sameFile reports whether a and b name the same file: the same existing
// file, whatever the spelling (relative or absolute, through a symlinked
// directory or a symlink to the file), or, when one does not exist yet, the
// same path once made absolute with its directory's symlinks resolved. It
// only stats the paths, so a FIFO is not opened.
func sameFile(a, b string) bool {
	if ia, err := os.Stat(a); err == nil {
		if ib, err := os.Stat(b); err == nil {
			return os.SameFile(ia, ib)
		}
	}
	ra, rb := resolvePath(a), resolvePath(b)
	return ra != "" && ra == rb
}

// resolvePath makes p absolute and resolves the symlinks of its directory;
// "" if p cannot be made absolute.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return ""
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Join(dir, filepath.Base(abs))
	}
	return abs
}

// readRegularFile reads path, following symlinks, if it is a regular file of
// at most maxBytes. The type is checked before opening, because opening a
// FIFO blocks, and again on the open file in case path was swapped.
func readRegularFile(path string, maxBytes int64) ([]byte, error) {
	notRegular := fmt.Errorf("%s is not a regular file", path)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, notRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err = f.Stat(); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, notRegular
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxBytes)
	}
	return data, nil
}

// writeStdout writes the report to stdout, a table colored if stdout itself
// is a terminal (see writeSafeReport).
func writeStdout(stdout io.Writer, format string, f []report.Finding, s report.Summary, so report.SARIFOptions) error {
	return writeSafeReport(stdout, format, f, s, format == "table" && report.UseColor(stdout), so)
}

// writeSafeReport is writeReport with a table passed through a ciLogWriter,
// on stdout or in an --out file alike: a CI job may print either. JSON,
// SARIF and JUnit already escape log commands inside their strings.
func writeSafeReport(w io.Writer, format string, f []report.Finding, s report.Summary, color bool, so report.SARIFOptions) error {
	if format != "table" {
		return writeReport(w, format, f, s, color, so)
	}
	cw := newCILogWriter(w)
	if err := writeReport(cw, format, f, s, color, so); err != nil {
		return err
	}
	return cw.Flush()
}

// sarifOptions makes SARIF URIs relative to the working directory when root
// (the resolved, absolute --path) is inside it: in the CI templates that is
// the repository root, which code scanning resolves URIs against. Otherwise
// they stay relative to root, with root's file URI as their base.
func sarifOptions(root string) report.SARIFOptions {
	if cwd, err := os.Getwd(); err == nil {
		if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
			cwd = resolved
		}
		if rel, err := filepath.Rel(cwd, root); err == nil && (rel == "." || filepath.IsLocal(rel)) {
			return report.SARIFOptions{PathPrefix: filepath.ToSlash(rel)}
		}
	}
	p := filepath.ToSlash(root)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a Windows drive path, C:/x
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return report.SARIFOptions{RootURI: (&url.URL{Scheme: "file", Path: p}).String()}
}

func writeReport(w io.Writer, format string, f []report.Finding, s report.Summary, color bool, so report.SARIFOptions) error {
	tool := report.ToolInfo{Name: "orbit", Version: buildinfo.Version, InformationURI: "https://github.com/orchesta/orbit"}
	switch format {
	case "json":
		return report.WriteJSON(w, f, s, tool)
	case "sarif":
		return report.WriteSARIF(w, f, s, tool, so)
	case "junit":
		return report.WriteJUnit(w, f, s)
	default:
		return report.WriteTableColor(w, f, s, color)
	}
}

// writeSummary prints the counts, the threshold verdict and the warnings,
// each line prefixed "orbit: ", so the CI log shows the result whatever the
// report format.
func writeSummary(w io.Writer, s report.Summary) {
	var buf bytes.Buffer
	_ = report.WriteTable(&buf, nil, s) // no findings: summary and warnings only
	if s.Threshold == "" && !s.FailOnKEV {
		buf.WriteString("no failure threshold (--fail-on none)\n")
	}
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		fmt.Fprintf(w, "orbit: %s\n", sc.Text())
	}
}
