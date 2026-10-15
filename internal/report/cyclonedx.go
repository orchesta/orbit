package report

import (
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/spdx"
)

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxLicense struct {
	License    *cdxNamedLicense `json:"license,omitempty"`
	Expression string           `json:"expression,omitempty"`
}

type cdxNamedLicense struct {
	Name string `json:"name"`
}

type cdxExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxOccurrence struct {
	Location string `json:"location"`
}

type cdxEvidence struct {
	Occurrences []cdxOccurrence `json:"occurrences,omitempty"`
}

type cdxComponent struct {
	Type               string           `json:"type"`
	BOMRef             string           `json:"bom-ref,omitempty"`
	Group              string           `json:"group,omitempty"`
	Name               string           `json:"name"`
	Version            string           `json:"version,omitempty"`
	Scope              string           `json:"scope,omitempty"`
	Licenses           []cdxLicense     `json:"licenses,omitempty"`
	PURL               string           `json:"purl,omitempty"`
	ExternalReferences []cdxExternalRef `json:"externalReferences,omitempty"`
	Evidence           *cdxEvidence     `json:"evidence,omitempty"`
	Properties         []cdxProperty    `json:"properties,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxVulnRef struct {
	ID     string    `json:"id"`
	Source cdxSource `json:"source"`
}

type cdxRating struct {
	Source   cdxSource `json:"source"`
	Severity string    `json:"severity"`
}

type cdxAdvisory struct {
	URL string `json:"url"`
}

type cdxAffectedVersion struct {
	Version string `json:"version"`
	Status  string `json:"status"`
}

type cdxAffects struct {
	Ref      string               `json:"ref"`
	Versions []cdxAffectedVersion `json:"versions,omitempty"`
}

type cdxAnalysis struct {
	State    string   `json:"state"`
	Response []string `json:"response,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

type cdxVulnerability struct {
	ID             string        `json:"id"`
	Source         cdxSource     `json:"source"`
	References     []cdxVulnRef  `json:"references,omitempty"`
	Ratings        []cdxRating   `json:"ratings"`
	Description    string        `json:"description,omitempty"`
	Detail         string        `json:"detail,omitempty"`
	Recommendation string        `json:"recommendation,omitempty"`
	Advisories     []cdxAdvisory `json:"advisories,omitempty"`
	Analysis       *cdxAnalysis  `json:"analysis,omitempty"`
	Affects        []cdxAffects  `json:"affects"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxMetadata struct {
	Timestamp string `json:"timestamp"`
	Tools     struct {
		Components []cdxComponent `json:"components"`
	} `json:"tools"`
	Component cdxComponent `json:"component"`
}

type cdxBOM struct {
	Schema          string             `json:"$schema"`
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        cdxMetadata        `json:"metadata"`
	Components      []cdxComponent     `json:"components"`
	Dependencies    []cdxDependency    `json:"dependencies"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

// cdxRootRef is the bom-ref of the scanned project; purls start with "pkg:".
const cdxRootRef = "root"

// osvSource names osv.dev, where orbit looks advisories up, as the source.
func osvSource(id string) cdxSource {
	return cdxSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + purlEscape(id)}
}

// cdxLicenses writes a valid SPDX expression as an expression and any
// other text as a named license, so it is kept but not claimed to be SPDX.
func cdxLicenses(l string) []cdxLicense {
	if l == "" || l == "NONE" || l == "NOASSERTION" {
		return nil
	}
	if expr := spdx.Normalize(l); expr != "" {
		return []cdxLicense{{Expression: expr}}
	}
	return []cdxLicense{{License: &cdxNamedLicense{Name: l}}}
}

func cdxComponentOf(p *sbomPackage) cdxComponent {
	c := cdxComponent{
		Type: "library", BOMRef: p.Ref, Name: p.Name,
		Version: nativeVersion(p.Ecosystem, p.Version), PURL: p.PURL,
		Scope: "required", Licenses: cdxLicenses(p.License),
		Properties: []cdxProperty{
			{Name: "orbit:direct", Value: strconv.FormatBool(p.Direct)},
			{Name: "orbit:ecosystem", Value: string(p.Ecosystem)},
			{Name: "orbit:resolved", Value: strconv.FormatBool(p.Resolved)},
		},
	}
	if p.Dev {
		c.Scope = "optional"
	}
	if p.Ecosystem == entity.EcosystemNpm && strings.HasPrefix(p.Name, "@") {
		if i := strings.IndexByte(p.Name, '/'); i > 0 {
			c.Group, c.Name = p.Name[:i], p.Name[i+1:]
		}
	}
	if len(p.Manifests) > 0 {
		c.Evidence = &cdxEvidence{}
		for _, m := range p.Manifests {
			c.Evidence.Occurrences = append(c.Evidence.Occurrences, cdxOccurrence{Location: m})
		}
	}
	return c
}

// cdxRecommendation is the advice for finding x on package p, as in the
// SARIF message. A known malicious package is to be removed or replaced,
// naming the clean release a non-MAL advisory gives, if any. Otherwise the
// advice is the upgrade to the fixed version, or none without one; when
// the package has a malicious finding (malicious), the advice for its other
// advisories, with or without a fix, ends in removalHint.
func cdxRecommendation(x Finding, p *sbomPackage, malicious bool) string {
	fix := fixedIn(x.Vulnerability)
	if fix != "" {
		fix = nativeVersion(p.Ecosystem, fix)
	}
	switch {
	case x.Malicious && fix != "":
		return "Remove or replace " + p.Name + ": it is a known malicious package (" + maliciousID(x.Vulnerability) + ") (fixed in " + fix + ")."
	case x.Malicious:
		return "Remove or replace " + p.Name + ": it is a known malicious package (" + maliciousID(x.Vulnerability) + ")."
	case fix != "" && malicious:
		return "Upgrade " + p.Name + " to " + fix + removalHint
	case fix != "":
		return "Upgrade " + p.Name + " to " + fix + "."
	case malicious:
		return "No fix available" + removalHint
	}
	return ""
}

// WriteCycloneDX writes a CycloneDX 1.6 JSON BOM: the scanned project as
// metadata.component, one component per package (see sbomPackages), a
// dependency graph that lists only the project's direct dependencies, since
// the analyzers do not record which package pulled in a transitive one, and
// one vulnerability per advisory and package, in finding order. A known
// malicious package is recommended for removal, not an upgrade, in all of its
// advisories. affects lists the installed version only when it is a concrete
// version, and the fixed one. Ignored
// findings are kept as accepted risks: analysis.state "exploitable" with
// response "will_not_fix" and the ignore reason as detail, never
// "not_affected", which would claim the component is unaffected. KEV, EPSS,
// baseline and license policy results are not written: an SBOM is an
// inventory, not a policy result.
func WriteCycloneDX(w io.Writer, f []Finding, s Summary, tool ToolInfo, opts SBOMOptions) error {
	pkgs, byDep := sbomPackages(s.Deps)
	bom := cdxBOM{
		Schema:          "http://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.6",
		SerialNumber:    "urn:uuid:" + opts.Serial.String(),
		Version:         1,
		Components:      []cdxComponent{},
		Vulnerabilities: []cdxVulnerability{},
	}
	bom.Metadata.Timestamp = sbomTime(opts.Now)
	toolComp := cdxComponent{Type: "application", Name: tool.Name, Version: tool.Version}
	if tool.InformationURI != "" {
		toolComp.ExternalReferences = []cdxExternalRef{{Type: "website", URL: tool.InformationURI}}
	}
	bom.Metadata.Tools.Components = []cdxComponent{toolComp}
	bom.Metadata.Component = cdxComponent{Type: "application", BOMRef: cdxRootRef, Name: rootName(opts)}

	root := cdxDependency{Ref: cdxRootRef, DependsOn: []string{}}
	for _, p := range pkgs {
		bom.Components = append(bom.Components, cdxComponentOf(p))
		if p.Direct {
			root.DependsOn = append(root.DependsOn, p.Ref)
		}
	}
	slices.Sort(root.DependsOn)
	bom.Dependencies = []cdxDependency{root}

	// A package with a malicious finding in any manifest is to be removed,
	// whatever its other advisories say.
	malicious := map[*sbomPackage]bool{}
	for _, x := range f {
		if p := byDep[x.Dependency.ID]; p != nil && x.Malicious {
			malicious[p] = true
		}
	}

	// One entry per (advisory, package): the same package found in two
	// manifests is one component. It is ignored only if every finding is.
	index := map[string]int{}
	for _, x := range f {
		v, p := x.Vulnerability, byDep[x.Dependency.ID]
		if p == nil {
			continue
		}
		key := strings.ToUpper(v.OSVID) + "\x00" + p.Ref
		if i, ok := index[key]; ok {
			if !x.Ignored {
				bom.Vulnerabilities[i].Analysis = nil
			}
			continue
		}
		index[key] = len(bom.Vulnerabilities)
		cv := cdxVulnerability{
			ID: v.OSVID, Source: osvSource(v.OSVID),
			Ratings:        []cdxRating{{Source: osvSource(v.OSVID), Severity: cdxSeverity(v.Severity)}},
			Description:    v.Summary,
			Detail:         v.Details,
			Recommendation: cdxRecommendation(x, p, malicious[p]),
			Affects:        []cdxAffects{{Ref: p.Ref}},
		}
		for _, a := range v.Aliases {
			cv.References = append(cv.References, cdxVulnRef{ID: a, Source: osvSource(a)})
		}
		for _, r := range v.References {
			if webURL(r) {
				cv.Advisories = append(cv.Advisories, cdxAdvisory{URL: r})
			}
		}
		// A declared range is not a version: only a concrete one is affected.
		if cur := nativeVersion(p.Ecosystem, p.Version); exactNativeVersion(p.Ecosystem, cur) {
			cv.Affects[0].Versions = append(cv.Affects[0].Versions, cdxAffectedVersion{Version: cur, Status: "affected"})
		}
		if fix := fixedIn(v); fix != "" {
			cv.Affects[0].Versions = append(cv.Affects[0].Versions,
				cdxAffectedVersion{Version: nativeVersion(p.Ecosystem, fix), Status: "unaffected"})
		}
		if x.Ignored {
			detail := "Ignored in .orbitignore"
			if x.IgnoreReason != "" {
				detail += ": " + x.IgnoreReason
			}
			cv.Analysis = &cdxAnalysis{State: "exploitable", Response: []string{"will_not_fix"}, Detail: detail}
		}
		bom.Vulnerabilities = append(bom.Vulnerabilities, cv)
	}
	return encodeJSON(w, bom)
}

// cdxSeverity maps orbit's severities onto the CycloneDX enum, which has
// the same names; anything else is "unknown".
func cdxSeverity(s entity.Severity) string {
	switch s {
	case entity.SeverityCritical, entity.SeverityHigh, entity.SeverityMedium, entity.SeverityLow:
		return string(s)
	}
	return "unknown"
}
