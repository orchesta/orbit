package report

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/orchesta/orbit/internal/domain/entity"
)

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

// sarifRootID is the uriBaseId of artifact URIs relative to RootURI.
const sarifRootID = "ORBITROOT"

// artifactLocation turns a manifest path (relative to the scanned
// directory) into a URI reference: prefixed with PathPrefix, or relative to
// RootURI, and percent-encoded per segment. ":" is encoded as well, so a
// first segment cannot be read as a URI scheme.
func (o SARIFOptions) artifactLocation(manifest string) sarifArtifactLocation {
	p := manifest
	var base string
	if o.RootURI != "" {
		base = sarifRootID
	} else if o.PathPrefix != "" && o.PathPrefix != "." {
		p = path.Join(o.PathPrefix, manifest)
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = strings.ReplaceAll(url.PathEscape(seg), ":", "%3A")
	}
	return sarifArtifactLocation{URI: strings.Join(segs, "/"), URIBaseID: base}
}

func securitySeverity(s entity.Severity) string {
	switch s {
	case entity.SeverityCritical:
		return "9.5"
	case entity.SeverityHigh:
		return "7.5"
	case entity.SeverityMedium:
		return "5.0"
	case entity.SeverityLow:
		return "2.0"
	}
	return "0"
}

func sarifLevel(s entity.Severity) string {
	switch s {
	case entity.SeverityCritical, entity.SeverityHigh:
		return "error"
	case entity.SeverityMedium:
		return "warning"
	}
	return "note"
}

// maliciousSecuritySeverity rates a known malicious package above every
// scored advisory; GitHub code scanning shows 9.0 and above as critical.
const maliciousSecuritySeverity = "10.0"

// maliciousRank orders a malicious finding above every severity when a
// rule's security-severity is chosen.
const maliciousRank = 5

// affectedText is "<pkg>@<version> is affected by <id>", or for a malicious
// package "<pkg>@<version> is a known malicious package (<MAL- id>)".
func affectedText(x Finding) string {
	d, v := x.Dependency, x.Vulnerability
	if x.Malicious {
		return d.Name + "@" + d.CurrentVersion + " is a known malicious package (" + maliciousID(v) + ")"
	}
	return d.Name + "@" + d.CurrentVersion + " is affected by " + v.OSVID
}

// SARIFOptions says how manifest paths, which are relative to the scanned
// directory, become artifact URIs.
type SARIFOptions struct {
	// PathPrefix is the scanned directory relative to the working directory
	// (slash-separated; "" or "." for the working directory itself).
	PathPrefix string
	// RootURI, if set, is the absolute URI of the scanned directory, ending
	// in "/". URIs then stay relative to it, under the base ID ORBITROOT.
	RootURI string
}

// WriteSARIF writes a SARIF 2.1.0 log with one rule per distinct advisory. A
// rule with a malicious finding is tagged "malicious" and rated 10.0. A rule listed in CISA KEV is also tagged "known-exploited";
// its security-severity is not raised.
func WriteSARIF(w io.Writer, f []Finding, _ Summary, tool ToolInfo, opts SARIFOptions) error {
	rules := []sarifRule{}
	ruleIdx := map[string]int{}
	ruleRank := map[string]int{}
	results := []sarifResult{}
	for _, x := range f {
		v, d := x.Vulnerability, x.Dependency
		rank, score, level := severityRank(v.Severity), securitySeverity(v.Severity), sarifLevel(v.Severity)
		if x.Malicious {
			rank, score, level = maliciousRank, maliciousSecuritySeverity, "error"
		}
		i, ok := ruleIdx[v.OSVID]
		if !ok {
			i = len(rules)
			ruleIdx[v.OSVID] = i
			ruleRank[v.OSVID] = rank
			rules = append(rules, sarifRule{
				ID:         v.OSVID,
				Properties: map[string]any{"security-severity": score},
			})
		} else if rank > ruleRank[v.OSVID] {
			ruleRank[v.OSVID] = rank
			rules[i].Properties["security-severity"] = score
		}
		if x.Malicious {
			addRuleTag(rules[i].Properties, "malicious")
		}
		if v.KEV {
			addRuleTag(rules[i].Properties, "known-exploited")
		}
		// The first non-empty text in finding order wins.
		if rules[i].ShortDescription.Text == "" {
			rules[i].ShortDescription.Text = v.Summary
		}
		if rules[i].HelpURI == "" && len(v.References) > 0 {
			rules[i].HelpURI = v.References[0]
		}
		msg := affectedText(x)
		switch fv := fixedIn(v); {
		case x.Malicious && fv != "":
			// fv comes from a member that is not a MAL- advisory (highestFix).
			msg += "; remove or replace it (fixed in " + fv + ")"
		case x.Malicious:
			msg += "; remove or replace it"
		case fv != "":
			msg += " (fixed in " + fv + ")"
		default:
			msg += " (no fix available)"
		}
		msg += exploitSuffix(v)
		var r sarifResult
		r.RuleID, r.Level, r.Message = v.OSVID, level, sarifText{msg}
		r.Properties = exploitProperties(v)
		r.Locations = make([]sarifLocation, 1)
		r.Locations[0].PhysicalLocation.ArtifactLocation = opts.artifactLocation(d.ManifestFile)
		sum := sha256.Sum256([]byte(strings.Join([]string{v.OSVID, string(d.Ecosystem), d.Name, d.CurrentVersion, d.ManifestFile}, "|")))
		r.PartialFingerprints = map[string]string{"orbit/v1": hex.EncodeToString(sum[:])}
		if x.Ignored {
			r.Suppressions = []sarifSuppression{{Kind: "external", Justification: x.IgnoreReason}}
		}
		results = append(results, r)
	}
	for i := range rules {
		if rules[i].ShortDescription.Text == "" {
			rules[i].ShortDescription.Text = rules[i].ID
		}
	}
	run := map[string]any{
		"tool": map[string]any{"driver": map[string]any{
			"name": tool.Name, "rules": rules,
		}},
		"results": results,
	}
	if opts.RootURI != "" {
		run["originalUriBaseIds"] = map[string]any{sarifRootID: map[string]string{"uri": opts.RootURI}}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    []any{run},
	}
	driver := doc["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)
	if tool.Version != "" {
		driver["version"] = tool.Version
	}
	if tool.InformationURI != "" {
		driver["informationUri"] = tool.InformationURI
	}
	return encodeJSON(w, doc)
}
