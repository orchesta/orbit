package report

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/aligoren/orbit/internal/domain/entity"
)

type jsonTool struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"information_uri"`
}

type jsonSummary struct {
	Dependencies int                     `json:"dependencies"`
	Vulnerable   int                     `json:"vulnerable"`
	BySeverity   map[entity.Severity]int `json:"by_severity"`
	Threshold    string                  `json:"threshold"`
	Failed       bool                    `json:"failed"`
	Warnings     []string                `json:"warnings"`
}

type jsonDependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Manifest  string `json:"manifest"`
	Direct    bool   `json:"direct"`
	Dev       bool   `json:"dev"`
	Resolved  bool   `json:"resolved"`
}

type jsonFinding struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases"`
	Severity     string   `json:"severity"`
	Summary      string   `json:"summary"`
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	Ecosystem    string   `json:"ecosystem"`
	Manifest     string   `json:"manifest"`
	FixedVersion *string  `json:"fixed_version"`
	References   []string `json:"references"`
	Ignored      bool     `json:"ignored"`
	IgnoreReason string   `json:"ignore_reason"`
}

type jsonReport struct {
	SchemaVersion int              `json:"schema_version"`
	Tool          jsonTool         `json:"tool"`
	Summary       jsonSummary      `json:"summary"`
	Dependencies  []jsonDependency `json:"dependencies"`
	Findings      []jsonFinding    `json:"findings"`
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// WriteJSON writes the stable schema_version 1 report. "#" in "##vso[" and
// "##[" is written as \u0023 (see neutraliseJSON).
func WriteJSON(w io.Writer, f []Finding, s Summary, tool ToolInfo) error {
	r := jsonReport{
		SchemaVersion: 1,
		Tool:          jsonTool{tool.Name, tool.Version, tool.InformationURI},
		Summary: jsonSummary{
			Dependencies: s.Dependencies, Vulnerable: s.Vulnerable, BySeverity: s.BySeverity,
			Threshold: string(s.Threshold), Failed: s.Failed, Warnings: nonNil(s.Warnings),
		},
		Dependencies: []jsonDependency{},
		Findings:     []jsonFinding{},
	}
	r.Summary.BySeverity = map[entity.Severity]int{}
	for _, sev := range severityOrder {
		r.Summary.BySeverity[sev] = s.BySeverity[sev]
	}
	for _, d := range s.Deps {
		r.Dependencies = append(r.Dependencies, jsonDependency{d.Name, d.CurrentVersion, string(d.Ecosystem),
			d.ManifestFile, d.IsDirect, d.IsDev, d.IsResolved})
	}
	for _, x := range f {
		v, d := x.Vulnerability, x.Dependency
		var fix *string
		if fv := fixedIn(v); fv != "" {
			fix = &fv
		}
		r.Findings = append(r.Findings, jsonFinding{
			ID: v.OSVID, Aliases: nonNil(v.Aliases), Severity: string(v.Severity), Summary: v.Summary,
			Package: d.Name, Version: d.CurrentVersion, Ecosystem: string(d.Ecosystem), Manifest: d.ManifestFile,
			FixedVersion: fix, References: nonNil(v.References), Ignored: x.Ignored, IgnoreReason: x.IgnoreReason,
		})
	}
	return encodeJSON(w, r)
}

// encodeJSON writes v as indented JSON with CI log commands neutralised.
func encodeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(neutraliseJSON(buf.Bytes()))
	return err
}
