// Package engine analyzes a checked-out source tree without a database: it
// finds and parses manifests and lockfiles, resolves them into a dependency
// list, optionally asks the package registries for latest versions, and looks
// up known vulnerabilities. The server's scan worker and the CLI share it.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
	"github.com/orchesta/orbit/internal/infrastructure/git"
)

// VulnLookup finds the known vulnerabilities of deps without persisting
// them; vulnerability.UseCase.Lookup implements it. Each returned
// vulnerability's DependencyID is the ID of one of deps, and the int counts
// the dependencies with at least one vulnerability.
type VulnLookup interface {
	Lookup(ctx context.Context, deps []*entity.Dependency) ([]*entity.Vulnerability, int, error)
}

// ExploitEnricher adds exploit signals (CISA KEV, FIRST EPSS) to
// vulnerabilities in place and says which sources answered;
// *exploit.Enricher implements it.
type ExploitEnricher interface {
	Enrich(ctx context.Context, vulns []*entity.Vulnerability) exploit.Result
}

// LicenseFetcher looks up the license of one package version, for example
// on deps.dev; depsdev.Client implements it. It returns a normalised SPDX
// expression, or "" with no error when the source has no SPDX license for
// the version or does not know it. An error means the lookup itself failed.
type LicenseFetcher interface {
	License(ctx context.Context, eco entity.Ecosystem, name, version string) (string, error)
}

// Options tunes an Engine.
type Options struct {
	CheckLatest bool         // query registries for the latest version (outdated info)
	Concurrency int          // registry lookups in flight; default 5
	Logger      *slog.Logger // nil discards logs
	// Exploit adds KEV and EPSS data after the vulnerability lookup; nil
	// skips it (orbit scan --no-exploit-data, ORBIT_EXPLOIT_ENABLED=false).
	Exploit ExploitEnricher
	// ExploitTimeout bounds Exploit; default 60s. Running out is a warning.
	ExploitTimeout time.Duration
	// SkipVia leaves Dependency.Via unset, so lockfiles' dependency graphs
	// are not walked. The server sets it, since it does not store Via.
	SkipVia bool
	// Licenses, if set, is asked for the license of every dependency with
	// an exact version whose lockfile records none. nil keeps the lockfile
	// licenses only.
	Licenses LicenseFetcher
	// LicenseConcurrency is the number of license lookups in flight;
	// default 10.
	LicenseConcurrency int
}

// defaultConcurrency is the number of registry lookups in flight when
// Options.Concurrency is not set.
const defaultConcurrency = 5

// defaultExploitTimeout bounds the exploit data step when
// Options.ExploitTimeout is not set.
const defaultExploitTimeout = 60 * time.Second

// defaultLicenseConcurrency is the number of license lookups in flight when
// Options.LicenseConcurrency is not set.
const defaultLicenseConcurrency = 10

// Engine analyzes source trees. It is safe for concurrent use.
type Engine struct {
	registry *analyzer.Registry
	lookup   VulnLookup
	files    *git.LocalGit
	opts     Options
	logger   *slog.Logger
}

// New creates an Engine. Production callers must always pass a non-nil
// lookup: a nil lookup skips the vulnerability check entirely and is meant
// only for tests. (It must be an untyped nil; a nil pointer inside the
// interface is not detected and panics.)
func New(registry *analyzer.Registry, lookup VulnLookup, opts Options) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.ExploitTimeout <= 0 {
		opts.ExploitTimeout = defaultExploitTimeout
	}
	if opts.LicenseConcurrency <= 0 {
		opts.LicenseConcurrency = defaultLicenseConcurrency
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Engine{registry: registry, lookup: lookup, files: git.NewLocalGit(), opts: opts, logger: logger}
}

// WithLogger returns a copy of e that logs to logger, for example one
// carrying the repository being scanned. e itself is unchanged; the copy
// shares e's registry and lookup.
func (e *Engine) WithLogger(logger *slog.Logger) *Engine {
	c := *e
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	c.logger = logger
	c.opts.Logger = logger
	return &c
}

// Result is what Analyze found.
type Result struct {
	Dependencies    []*entity.Dependency    // IDs set; RepositoryID/ScanResultID are uuid.Nil
	Vulnerabilities []*entity.Vulnerability // DependencyID points into Dependencies
	VulnerableDeps  int
	OutdatedDeps    int
	Manifests       []string // files that were parsed, relative to root
	Warnings        []string // unreadable/unparseable files, parse warnings, unresolved-version notice, license lookup and exploit data failures
	// Exploit says which exploit data sources answered; nil when
	// Options.Exploit is nil or the vulnerability check failed.
	Exploit *exploit.Result
	// LicenseLookupFailed counts the packages whose license lookup failed
	// (see Options.Licenses); their License stays "". A warning names the
	// first error.
	LicenseLookupFailed int
}

// ErrVulnerabilityCheck marks a failed advisory lookup: the error Analyze
// returns then is a *VulnCheckError, and errors.Is(err, ErrVulnerabilityCheck)
// holds. Analyze still returns the Result with Dependencies filled, so callers
// can keep them.
var ErrVulnerabilityCheck = errors.New("vulnerability check failed")

// VulnCheckError is a failed advisory lookup; Err is the lookup's error.
type VulnCheckError struct{ Err error }

func (e *VulnCheckError) Error() string { return ErrVulnerabilityCheck.Error() + ": " + e.Err.Error() }

// Unwrap returns the lookup's error.
func (e *VulnCheckError) Unwrap() error { return e.Err }

// Is reports whether target is ErrVulnerabilityCheck.
func (e *VulnCheckError) Is(target error) bool { return target == ErrVulnerabilityCheck }

// Analyze scans the checkout at root. Symlinks and the directories in
// git.SkipDirs are not followed. A file that cannot be read or parsed is
// reported in Warnings, not as an error. If ctx ends during the analysis,
// Analyze returns ctx.Err() and no Result.
func (e *Engine) Analyze(ctx context.Context, root string) (*Result, error) {
	paths, err := e.files.WalkFiles(root)
	if err != nil {
		return nil, fmt.Errorf("file discovery failed: %w", err)
	}

	var manifests []analyzer.ManifestMatch
	for _, p := range paths {
		manifests = append(manifests, e.registry.DetectManifestFiles(p)...)
	}
	e.logger.Info("discovered manifests", slog.Int("count", len(manifests)))

	res := &Result{}
	if len(manifests) == 0 {
		// Only the CLI shows Warnings; a wrong --path should not pass as a
		// clean scan without a word.
		res.Warnings = append(res.Warnings, "no manifest or lockfile found under "+root)
		res.Exploit = e.skippedExploit()
		return res, nil
	}

	parsedFiles := e.parseFiles(root, manifests, res)

	unresolved := 0
	for _, rd := range analyzer.Resolve(parsedFiles) {
		dep := entity.NewDependency(uuid.Nil, uuid.Nil, rd.Name, rd.CurrentVersion, rd.ManifestFile, rd.Ecosystem)
		dep.IsDirect = rd.IsDirect
		dep.IsResolved = rd.Resolved
		dep.IsDev = rd.Dev
		dep.Via = rd.Via
		dep.License = rd.License
		res.Dependencies = append(res.Dependencies, dep)
		// Go has no lockfile: go.mod already lists the versions the build
		// resolves to, so its rows are not counted.
		if !rd.Resolved && rd.Ecosystem != entity.EcosystemGo {
			unresolved++
		}
	}
	if w := unresolvedWarning(unresolved); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	e.logger.Info("parsed dependencies", slog.Int("count", len(res.Dependencies)))

	if e.opts.CheckLatest {
		res.OutdatedDeps = e.checkLatestVersions(ctx, res.Dependencies)
	}
	if e.opts.Licenses != nil {
		e.fetchLicenses(ctx, res)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if e.lookup != nil {
		vulns, vulnerable, err := e.lookup.Lookup(ctx, res.Dependencies)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil {
			// Not logged here: the caller reports it (the CLI prints it,
			// the server records the failed scan).
			return res, &VulnCheckError{Err: err}
		}
		res.Vulnerabilities = vulns
		res.VulnerableDeps = vulnerable
		if e.opts.Exploit != nil {
			if err := e.enrich(ctx, res); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}

// enrich adds exploit signals within ExploitTimeout. A source that fails
// or runs out of time becomes a warning; the vulnerabilities stay as the
// lookup returned them. Only the end of ctx itself is returned.
func (e *Engine) enrich(ctx context.Context, res *Result) error {
	ectx, cancel := context.WithTimeout(ctx, e.opts.ExploitTimeout)
	defer cancel()
	er := e.opts.Exploit.Enrich(ectx, res.Vulnerabilities)
	if err := ctx.Err(); err != nil {
		return err
	}
	res.Exploit = &er
	res.Warnings = append(res.Warnings, er.Warnings()...)
	return nil
}

// skippedExploit is the exploit result of a scan with nothing to look up,
// or nil when exploit data is off.
func (e *Engine) skippedExploit() *exploit.Result {
	if e.opts.Exploit == nil {
		return nil
	}
	skipped := exploit.SourceResult{Status: exploit.StatusSkipped}
	return &exploit.Result{KEV: skipped, EPSS: skipped}
}

// unresolvedWarning tells how many dependencies have only an approximate
// version because no lockfile pins them, or returns "" for none.
func unresolvedWarning(n int) string {
	switch n {
	case 0:
		return ""
	case 1:
		return "1 dependency has no lockfile; its version is approximate"
	}
	return fmt.Sprintf("%d dependencies have no lockfile; their versions are approximate", n)
}

// parseFiles reads and parses every matched file for analyzer.Resolve,
// recording the parsed paths in res.Manifests, and failures and parse
// warnings (see analyzer.OptionsParser), after the file's path, in
// res.Warnings.
// A manifest that cannot be read or parsed is dropped. A lockfile is still
// passed on, without dependencies and marked Failed, so its directory keeps
// its manifests' results; one that parses to nothing is not marked.
func (e *Engine) parseFiles(root string, manifests []analyzer.ManifestMatch, res *Result) []analyzer.ParsedFile {
	parsedFiles := make([]analyzer.ParsedFile, 0, len(manifests))
	seen := make(map[string]bool)
	for _, m := range manifests {
		slashPath := filepath.ToSlash(m.ManifestPath)
		file := analyzer.ParsedFile{Analyzer: m.Analyzer, Path: slashPath, Kind: m.Analyzer.Kind(slashPath)}
		msg := "failed to read manifest"
		maxBytes := int64(git.MaxManifestBytes)
		if file.Kind == analyzer.KindLockfile {
			maxBytes = git.MaxLockfileBytes
		}
		content, err := e.files.ReadFileLimit(root, m.ManifestPath, maxBytes)
		if err == nil {
			msg = "failed to parse manifest"
			var warnings []string
			file.Deps, warnings, err = analyzer.Parse(m.Analyzer, content, slashPath, analyzer.ParseOptions{SkipVia: e.opts.SkipVia})
			for _, w := range warnings {
				res.Warnings = append(res.Warnings, slashPath+": "+w)
			}
		}
		if err != nil {
			e.logger.Warn(msg,
				slog.String("path", m.ManifestPath),
				slog.String("error", err.Error()),
			)
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s %s: %v", msg, slashPath, err))
			if file.Kind != analyzer.KindLockfile {
				continue
			}
			file.Deps = nil
			file.Failed = true
		} else if !seen[slashPath] {
			seen[slashPath] = true
			res.Manifests = append(res.Manifests, slashPath)
		}
		parsedFiles = append(parsedFiles, file)
	}
	return parsedFiles
}

// checkLatestVersions asks the registries for the latest version of each
// package and records it on every row of that package, returning how many
// rows are outdated. With lockfiles a package often has several rows (one per
// installed version), so each (ecosystem, name) is looked up once.
func (e *Engine) checkLatestVersions(ctx context.Context, deps []*entity.Dependency) int {
	type pkgKey struct {
		eco  entity.Ecosystem
		name string
	}
	rowsByPkg := make(map[pkgKey][]*entity.Dependency)
	var pkgs []pkgKey
	for _, d := range deps {
		k := pkgKey{d.Ecosystem, d.Name}
		if _, seen := rowsByPkg[k]; !seen {
			pkgs = append(pkgs, k)
		}
		rowsByPkg[k] = append(rowsByPkg[k], d)
	}

	outdatedCount := 0
	sem := make(chan struct{}, e.opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, k := range pkgs {
		wg.Add(1)
		go func(k pkgKey, rows []*entity.Dependency) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release
			// A misbehaving registry response must not crash the process:
			// the package's rows just keep no latest version.
			defer func() {
				if r := recover(); r != nil {
					e.logger.Error("panic while checking latest version",
						slog.String("package", k.name),
						slog.Any("panic", r),
						slog.String("stack", string(debug.Stack())),
					)
				}
			}()

			a, ok := e.registry.Get(k.eco)
			if !ok {
				return
			}

			latest, err := a.GetLatestVersion(ctx, k.name)
			if err != nil {
				e.logger.Debug("failed to get latest version",
					slog.String("package", k.name),
					slog.String("error", err.Error()),
				)
				return
			}

			// Compute every row's update type before assigning any, so a
			// panic cannot leave the rows half updated.
			updateTypes := make([]string, len(rows))
			for i, d := range rows {
				updateTypes[i] = analyzer.CompareVersions(d.CurrentVersion, latest)
			}
			outdated := 0
			for i, d := range rows {
				d.LatestVersion = latest
				d.UpdateType = entity.UpdateType(updateTypes[i])
				d.IsOutdated = updateTypes[i] != "none"
				if d.IsOutdated {
					outdated++
				}
			}

			mu.Lock()
			outdatedCount += outdated
			mu.Unlock()
		}(k, rowsByPkg[k])
	}
	wg.Wait()
	return outdatedCount
}

// exactVersion reports whether d's version names one release, so a license
// lookup for it is meaningful: lockfile entries and exact pins (Resolved),
// go.mod versions, and NuGet project references with a plain version, which
// NuGet resolves to exactly that version when it exists. Manifest ranges
// such as "^1.2.0" are not looked up.
func exactVersion(d *entity.Dependency) bool {
	switch {
	case d.CurrentVersion == "":
		return false
	case d.IsResolved, d.Ecosystem == entity.EcosystemGo:
		return true
	case d.Ecosystem == entity.EcosystemNuGet:
		return !strings.ContainsAny(d.CurrentVersion, "[]()*, ")
	}
	return false
}

// fetchLicenses asks e.opts.Licenses for the license of every dependency
// with an exact version and no lockfile license, once per (ecosystem, name,
// version), and records it on every such row of that version; a lockfile
// license is never overwritten. At most e.opts.LicenseConcurrency lookups
// run at once. Failed lookups are counted in res.LicenseLookupFailed and
// summarised in one warning; a panicking fetcher counts as a failure. Once
// ctx ends no new lookup starts and failures are not counted: Analyze then
// returns ctx.Err().
func (e *Engine) fetchLicenses(ctx context.Context, res *Result) {
	type versionKey struct {
		eco           entity.Ecosystem
		name, version string
	}
	rows := make(map[versionKey][]*entity.Dependency)
	var keys []versionKey
	for _, d := range res.Dependencies {
		if d.License != "" || !exactVersion(d) {
			continue
		}
		k := versionKey{d.Ecosystem, d.Name, d.CurrentVersion}
		if _, seen := rows[k]; !seen {
			keys = append(keys, k)
		}
		rows[k] = append(rows[k], d)
	}
	if len(keys) == 0 {
		return
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failed   int
		firstErr error
	)
	sem := make(chan struct{}, e.opts.LicenseConcurrency)
	for _, k := range keys {
		wg.Add(1)
		go func(k versionKey) {
			defer wg.Done()
			select {
			case sem <- struct{}{}: // Acquire
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }() // Release
			license, err := e.safeLicense(ctx, k.eco, k.name, k.version)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if ctx.Err() == nil {
					failed++
					if firstErr == nil {
						firstErr = err
					}
				}
				return
			}
			for _, d := range rows[k] {
				d.License = license
			}
		}(k)
	}
	wg.Wait()
	e.logger.Info("looked up licenses", slog.Int("versions", len(keys)), slog.Int("failed", failed))
	if failed > 0 {
		res.LicenseLookupFailed = failed
		noun := "packages"
		if failed == 1 {
			noun = "package"
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("license lookup failed for %d %s: %v", failed, noun, firstErr))
	}
}

// safeLicense calls the fetcher, turning a panic into an error.
func (e *Engine) safeLicense(ctx context.Context, eco entity.Ecosystem, name, version string) (license string, err error) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("panic while looking up a license",
				slog.String("package", name),
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
			license, err = "", fmt.Errorf("license lookup for %s panicked", name)
		}
	}()
	return e.opts.Licenses.License(ctx, eco, name, version)
}
