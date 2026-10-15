package report

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/spdx"
)

const ignoreDateLayout = "2006-01-02"

// ParseIgnoreFile reads an .orbitignore file. Each non-blank, non-comment
// line is
//
//	<advisory-id> [expires=YYYY-MM-DD] [package=<name>] reason...
//	license:<SPDX-ID> package=<name> [expires=YYYY-MM-DD] reason...
//
// The second form accepts one license for one package under the license
// policy (see ApplyLicensePolicy); package= is required and the identifier
// must be on the SPDX list. It never suppresses an advisory.
// key=value options come right after the ID; the first token that is not
// key=value starts the reason, so a reason that itself begins with key=value
// is parsed as an option (and rejected if the key is unknown). A leading UTF-8
// BOM is ignored. Expiry is the end of that day in UTC. Errors
// carry the 1-based line number.
func ParseIgnoreFile(r io.Reader) (*IgnoreList, error) {
	list := &IgnoreList{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		if n == 1 {
			text = strings.TrimPrefix(text, "\ufeff")
		}
		line := strings.TrimSpace(text)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if isOption(fields[0]) {
			return nil, fmt.Errorf(".orbitignore line %d: expected an advisory ID, got %q", n, clip(fields[0]))
		}
		e := IgnoreEntry{ID: fields[0]}
		if prefix, rest, ok := strings.Cut(fields[0], ":"); ok && strings.EqualFold(prefix, "license") {
			if hint, ok := spdx.ExceptionHint(rest); ok {
				return nil, fmt.Errorf(".orbitignore line %d: license identifier %q %s", n, clip(rest), hint)
			}
			id, known := spdx.CanonicalID(rest)
			if !known || strings.HasSuffix(id, "+") {
				return nil, fmt.Errorf(".orbitignore line %d: unknown SPDX license identifier %q", n, clip(rest))
			}
			e.ID, e.License = "license:"+id, id
		}
		seen := map[string]bool{}
		i := 1
		for ; i < len(fields) && isOption(fields[i]); i++ {
			key, val, _ := strings.Cut(fields[i], "=")
			if seen[key] {
				return nil, fmt.Errorf(".orbitignore line %d: duplicate option %q", n, clip(key))
			}
			seen[key] = true
			switch key {
			case "expires":
				d, err := time.Parse(ignoreDateLayout, val)
				if err != nil {
					return nil, fmt.Errorf(".orbitignore line %d: invalid expires date %q (want YYYY-MM-DD)", n, clip(val))
				}
				e.Expires = d.AddDate(0, 0, 1) // end of day UTC; Match treats Expires as exclusive
			case "package":
				if val == "" {
					return nil, fmt.Errorf(".orbitignore line %d: package= needs a name", n)
				}
				e.Package = val
			default:
				return nil, fmt.Errorf(".orbitignore line %d: unknown option %q", n, clip(key))
			}
		}
		if e.License != "" {
			if e.Package == "" {
				return nil, fmt.Errorf(".orbitignore line %d: %s needs package=<name>", n, e.ID)
			}
			e.ID += " package=" + e.Package // how warnings name the entry
		}
		e.Reason = strings.Join(fields[i:], " ")
		list.Entries = append(list.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read .orbitignore: %w", err)
	}
	return list, nil
}

// maxEchoRunes caps how much of a token an error message repeats.
const maxEchoRunes = 64

// clip shortens tok to maxEchoRunes characters for an error message.
func clip(tok string) string {
	if r := []rune(tok); len(r) > maxEchoRunes {
		return string(r[:maxEchoRunes]) + "..."
	}
	return tok
}

// isOption reports whether tok looks like key=value (non-empty key).
func isOption(tok string) bool {
	i := strings.IndexByte(tok, '=')
	return i > 0
}

// expiryWarning describes an entry whose expiry has passed at now, or "".
func (e IgnoreEntry) expiryWarning(now time.Time) string {
	if e.Expires.IsZero() || now.Before(e.Expires) {
		return ""
	}
	last := e.Expires.Add(-time.Nanosecond).UTC().Format(ignoreDateLayout)
	return fmt.Sprintf("ignore entry %s expired on %s", e.ID, last)
}

// ignoreWarnings lists expired entries and active entries that were not
// used (used[i] reports whether Entries[i] matched a finding or cleared a
// license violation). It lists only advisory entries (License "") or only
// license entries, as licenses says. Sorted by the caller.
func (l *IgnoreList) ignoreWarnings(used []bool, now time.Time, licenses bool) []string {
	if l == nil {
		return nil
	}
	var out []string
	for i, e := range l.Entries {
		if (e.License != "") != licenses {
			continue
		}
		if w := e.expiryWarning(now); w != "" {
			out = append(out, w)
		} else if !used[i] {
			out = append(out, "unused ignore entry "+e.ID)
		}
	}
	sort.Strings(out)
	return out
}

// samePackage compares package names by ecosystem rules: PyPI uses PEP 503
// normalisation, NuGet is case-insensitive, everything else is exact.
func samePackage(eco entity.Ecosystem, a, b string) bool {
	switch eco {
	case entity.EcosystemPyPI:
		return pep503(a) == pep503(b)
	case entity.EcosystemNuGet:
		return strings.EqualFold(a, b)
	}
	return a == b
}

// pep503 lowercases and collapses runs of '-', '_' and '.' into one '-'.
func pep503(s string) string {
	var sb strings.Builder
	sep := false
	for _, r := range strings.ToLower(s) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep {
			sb.WriteByte('-')
			sep = false
		}
		sb.WriteRune(r)
	}
	if sep {
		sb.WriteByte('-')
	}
	return sb.String()
}
