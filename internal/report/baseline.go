package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

// Baseline is the set of findings of an earlier orbit JSON report. A finding
// is in the baseline when the report has a finding on the same ecosystem and
// package (see packageKey) whose IDs ({id} ∪ aliases, case-insensitive)
// share at least one ID with it. Versions and manifests are not compared, so
// an upgrade that keeps a vulnerability does not make it new.
type Baseline struct {
	// ToolVersion is the orbit version that wrote the report ("" if absent).
	ToolVersion string

	ids      map[baselineKey]map[string]bool // upper-cased IDs of all findings on a package
	findings int
}

type baselineKey struct {
	eco entity.Ecosystem
	pkg string
}

// baselineDoc is the part of the JSON report a baseline needs. Other fields,
// including those later plans add, are ignored.
type baselineDoc struct {
	SchemaVersion *int `json:"schema_version"`
	Tool          struct {
		Version string `json:"version"`
	} `json:"tool"`
	Findings *[]struct {
		ID        string   `json:"id"`
		Aliases   []string `json:"aliases"`
		Package   string   `json:"package"`
		Ecosystem string   `json:"ecosystem"`
	} `json:"findings"`
}

// ParseBaseline reads an orbit JSON report (schema_version 1, any orbit
// version). A leading UTF-8 BOM is ignored. Errors say what is wrong with the
// file; the caller adds its name.
func ParseBaseline(data []byte) (*Baseline, error) {
	data = bytes.TrimPrefix(data, []byte("\ufeff"))
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("the file is empty")
	}
	if len(data) >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)) {
		return nil, errors.New("the file is UTF-16 encoded; write the report with --out instead of a shell redirection")
	}
	var doc baselineDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not an orbit JSON report: %v", err)
	}
	if doc.SchemaVersion == nil {
		return nil, errors.New("not an orbit JSON report (no schema_version); create it with orbit scan --format json")
	}
	if *doc.SchemaVersion != 1 {
		return nil, fmt.Errorf("schema_version %d is not supported; this orbit reads schema_version 1", *doc.SchemaVersion)
	}
	if doc.Findings == nil {
		return nil, errors.New("not an orbit JSON report (no findings array)")
	}
	b := &Baseline{ToolVersion: doc.Tool.Version, ids: map[baselineKey]map[string]bool{}}
	for i, f := range *doc.Findings {
		if f.ID == "" || f.Package == "" || f.Ecosystem == "" {
			return nil, fmt.Errorf("finding %d has no id, package or ecosystem", i+1)
		}
		eco := entity.Ecosystem(f.Ecosystem)
		k := baselineKey{eco, packageKey(eco, f.Package)}
		set := b.ids[k]
		if set == nil {
			set = map[string]bool{}
			b.ids[k] = set
		}
		set[strings.ToUpper(f.ID)] = true
		for _, a := range f.Aliases {
			if a != "" {
				set[strings.ToUpper(a)] = true
			}
		}
		b.findings++
	}
	return b, nil
}

// Len is the number of findings in the baseline report.
func (b *Baseline) Len() int { return b.findings }

// Contains reports whether the advisory id (with its aliases) on package pkg
// of ecosystem eco is in the baseline. The union of a package's baseline IDs
// is enough: sharing an ID with any one baseline finding is the same as
// sharing an ID with the union.
func (b *Baseline) Contains(eco entity.Ecosystem, pkg, id string, aliases []string) bool {
	set := b.ids[baselineKey{eco, packageKey(eco, pkg)}]
	if set[strings.ToUpper(id)] {
		return true
	}
	for _, a := range aliases {
		if set[strings.ToUpper(a)] {
			return true
		}
	}
	return false
}

// packageKey normalises a package name with the shared ecosystem rules
// (analyzer.NameKey: PEP 503 for PyPI, case-insensitive for NuGet, exact
// otherwise), the same equivalence samePackage uses.
func packageKey(eco entity.Ecosystem, name string) string {
	return analyzer.NameKey(eco, name)
}
