package report

import (
	"regexp"
	"strings"
)

// CI agents run commands they find in a job's log: Azure Pipelines acts on
// "##vso[" and "##[" anywhere in a line, GitHub Actions on "::" at the start
// of a line (and on the legacy "##["). Advisory text, package names and
// manifest paths come from the scanned repository and osv.dev, so reports
// must not carry these sequences in a form an agent would run.

// ciCommandRE matches the Azure/legacy command prefixes, case-insensitively.
var ciCommandRE = regexp.MustCompile(`(?i)##(vso)?\[`)

// jsonHashes is "##" as two JSON escapes (backslash, u0023, twice).
const jsonHashes = "\\u0023\\u0023"

// neutraliseJSON escapes the "#" of every "##vso[" and "##[" in encoded JSON
// as a \u escape (see jsonHashes). Outside strings JSON has no "#", so the
// sequences can only be in strings, and the decoded values stay the same.
func neutraliseJSON(b []byte) []byte {
	return ciCommandRE.ReplaceAllFunc(b, func(m []byte) []byte {
		return append([]byte(jsonHashes), m[2:]...)
	})
}

// neutraliseXML does the same for encoded XML with the character reference
// &#35;; the sequences can only be in attribute values or text.
func neutraliseXML(b []byte) []byte {
	return ciCommandRE.ReplaceAllFunc(b, func(m []byte) []byte {
		return append([]byte(`&#35;&#35;`), m[2:]...)
	})
}

// singleLine replaces control characters (C0, DEL and C1, including CR, LF
// and ESC) and invalid UTF-8 with U+FFFD, so a table cell cannot start a new
// log line or send terminal escape sequences.
func singleLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return '\ufffd'
		}
		return r
	}, s)
}
