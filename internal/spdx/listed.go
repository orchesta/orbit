package spdx

import "strings"

// NormalizeListed is Normalize for a document that cannot define its own
// licenses, such as an SPDX 2.3 document without
// hasExtractedLicensingInfos: it returns the canonical expression only when
// every license in it is on the SPDX License List, and "" when s does not
// normalise, names a LicenseRef (with or without a DocumentRef), or is
// longer than MaxExpressionLen as input or as result.
func NormalizeListed(s string) string {
	e, err := parse(s)
	if err != nil || e.hasRef() {
		return ""
	}
	if out := e.String(); len(out) <= MaxExpressionLen {
		return out
	}
	return ""
}

// hasRef reports whether the expression names a LicenseRef.
func (e *expr) hasRef() bool {
	if e.op == "" {
		return strings.Contains(e.id, "LicenseRef-")
	}
	for _, a := range e.args {
		if a.hasRef() {
			return true
		}
	}
	return false
}
