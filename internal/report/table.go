package report

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
)

var severityOrder = []entity.Severity{
	entity.SeverityCritical, entity.SeverityHigh, entity.SeverityMedium, entity.SeverityLow, entity.SeverityUnknown,
}

// useColor is true only for a terminal writer and when NO_COLOR is unset.
func useColor(w io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func colorize(s string, sev entity.Severity) string {
	code := map[entity.Severity]string{
		entity.SeverityCritical: "1;31", entity.SeverityHigh: "31", entity.SeverityMedium: "33", entity.SeverityLow: "36",
	}[sev]
	if code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// WriteTable prints findings in severity order, the upgrade
// recommendations, then the license policy violations, followed by a
// summary and warnings. With nil findings it prints only the summary and
// warnings. Color is used only on a terminal with NO_COLOR unset. Control
// characters in cells and warnings are shown as U+FFFD, so every finding is
// one line.
func WriteTable(w io.Writer, f []Finding, s Summary) error {
	return writeTable(w, f, s, useColor(w))
}

// UseColor reports whether WriteTable would color its output on w: only for
// a terminal, and only when NO_COLOR is unset.
func UseColor(w io.Writer) bool { return useColor(w) }

// WriteTableColor is WriteTable with the color decision made by the caller,
// for a writer that wraps the terminal (see UseColor).
func WriteTableColor(w io.Writer, f []Finding, s Summary, color bool) error {
	return writeTable(w, f, s, color)
}

func writeTable(w io.Writer, f []Finding, s Summary, color bool) error {
	var err error
	printf := func(format string, a ...any) {
		if err == nil {
			_, err = fmt.Fprintf(w, format, a...)
		}
	}
	if len(f) > 0 {
		exploitCols := showExploit(s)
		header := []string{"SEVERITY"}
		if exploitCols {
			header = append(header, "KEV", "EPSS")
		}
		header = append(header, "ID", "PACKAGE")
		if s.ShowLicenses {
			header = append(header, "LICENSE")
		}
		header = append(header, "FIXED", "MANIFEST")
		rows := [][]string{header}
		for _, x := range f {
			fixed := fixedIn(x.Vulnerability)
			if fixed == "" {
				fixed = "-"
			}
			row := []string{severityCell(x, s)}
			if exploitCols {
				kev := "-"
				switch {
				case s.Exploit.KEV != string(exploit.StatusOK):
					kev = "?" // no catalog: "-" would read as "not in KEV"
				case x.Vulnerability.KEV:
					kev = "yes"
				}
				row = append(row, kev, formatEPSS(x.Vulnerability.EPSS))
			}
			row = append(row, singleLine(x.Vulnerability.OSVID),
				singleLine(x.Dependency.Name+"@"+x.Dependency.CurrentVersion))
			if s.ShowLicenses {
				row = append(row, singleLine(licenseCell(x.Dependency)))
			}
			row = append(row, singleLine(fixed), singleLine(x.Dependency.ManifestFile))
			rows = append(rows, row)
		}
		style := func(ri, ci int, c string) string {
			if ri == 0 || !color || f[ri-1].Ignored {
				return c
			}
			switch {
			case ci == 0:
				sev := f[ri-1].Vulnerability.Severity
				if f[ri-1].Malicious {
					sev = entity.SeverityCritical
				}
				return colorize(c, sev)
			case exploitCols && ci == 1 && f[ri-1].Vulnerability.KEV:
				return colorize(c, entity.SeverityCritical)
			}
			return c
		}
		for _, line := range alignRows(rows, style) {
			printf("%s\n", line)
		}
		printf("\n")
	}
	if lines := recommendationLines(s.Recommendations); len(lines) > 0 {
		for _, line := range lines {
			printf("%s\n", line)
		}
		printf("\n")
	}
	// A nil f is the summary-only call (cmd/orbit's writeSummary): the
	// violations are listed in the report, not again on stderr.
	if f != nil && len(s.LicenseViolations) > 0 {
		rows := [][]string{{"DENIED", "PACKAGE", "LICENSE", "MANIFEST"}}
		for _, v := range s.LicenseViolations {
			d := v.Dependency
			denied := strings.Join(v.Denied, ", ")
			if v.Ignored {
				denied += " (ignored)"
			}
			rows = append(rows, []string{singleLine(denied), singleLine(d.Name + "@" + d.CurrentVersion),
				singleLine(d.License), singleLine(d.ManifestFile)})
		}
		for _, line := range alignRows(rows, func(_, _ int, c string) string { return c }) {
			printf("%s\n", line)
		}
		printf("\n")
	}
	printf("%d dependencies, %d vulnerable", s.Dependencies, s.Vulnerable)
	var parts []string
	for _, sev := range severityOrder {
		if n := s.BySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) > 0 {
		printf(" (%s)", strings.Join(parts, ", "))
	}
	if s.Malicious > 0 {
		printf(", %d malicious", s.Malicious)
	}
	if s.Baseline {
		printf(", %d new", s.New)
	}
	printf("\n")
	if s.KEVFindings > 0 {
		printf("%d known exploited (CISA KEV)\n", s.KEVFindings)
	}
	// With a baseline both gate lines follow only the findings that count:
	// new ones and malicious packages (see gates).
	scope := ""
	if s.Baseline {
		scope = " (new findings and malicious packages)"
	}
	if s.Threshold != "" {
		// Only the severity and malicious gate: the KEV gate has its own
		// line below. The exit code follows s.Failed, which covers both.
		status := "passed"
		if s.ThresholdFailed {
			status = "FAILED"
		}
		printf("threshold %s%s: %s\n", s.Threshold, scope, status)
	}
	if s.FailOnKEV {
		status := "passed"
		if s.KEVFailed {
			status = "FAILED"
		}
		printf("fail on KEV%s: %s\n", scope, status)
	}
	if len(s.DeniedLicenses) > 0 {
		// Not scoped by the baseline: it does not filter license violations.
		printf("%s\n", licensePolicyLine(s))
	}
	for _, msg := range s.Warnings {
		printf("warning: %s\n", singleLine(msg))
	}
	return err
}

// severityCell is the SEVERITY column: the severity in capitals, followed by
// "(malicious)", "(ignored)", "(new)" or a combination. "new" is shown only
// with a baseline and not on ignored findings.
func severityCell(x Finding, s Summary) string {
	sev := strings.ToUpper(string(x.Vulnerability.Severity))
	var marks []string
	if x.Malicious {
		marks = append(marks, "malicious")
	}
	switch {
	case x.Ignored:
		marks = append(marks, "ignored")
	case s.Baseline && x.New:
		marks = append(marks, "new")
	}
	if len(marks) > 0 {
		sev += " (" + strings.Join(marks, ", ") + ")"
	}
	return sev
}

// alignRows pads every column but the last to its widest cell plus two
// spaces. style may decorate a cell (color) after its width is measured.
func alignRows(rows [][]string, style func(row, col int, cell string) string) []string {
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if n := utf8.RuneCountInString(c); n > widths[i] {
				widths[i] = n
			}
		}
	}
	lines := make([]string, 0, len(rows))
	for ri, r := range rows {
		var line strings.Builder
		for i, c := range r {
			line.WriteString(style(ri, i, c))
			if i < len(r)-1 {
				line.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)+2))
			}
		}
		lines = append(lines, line.String())
	}
	return lines
}

// recommendationLines renders the recommendations: a table of upgrades,
// the advisories without a known fix, and a caution. Nothing for none. A
// malicious package gets a removal note instead of an upgrade row; a fixed
// version that a non-malicious advisory of the group names is mentioned.
func recommendationLines(recs []Recommendation) []string {
	rows := [][]string{{"PACKAGE", "UPGRADE TO", "FIXES", "VIA", "MANIFEST"}}
	var notes []string
	anyVia := false
	for _, r := range recs {
		pkg := singleLine(r.Package + "@" + r.Current)
		switch {
		case r.Malicious:
			ids := append(slices.Clone(r.Fixes), r.NoFix...)
			slices.Sort(ids)
			note := "remove " + pkg + ": reported as malicious (" + singleLine(strings.Join(ids, ", ")) + ")"
			if r.Upgrade != "" {
				note += "; a non-malicious advisory names " + singleLine(r.Upgrade) + " as fixed"
			}
			notes = append(notes, note)
			continue
		case len(r.NoFix) > 0:
			notes = append(notes, pkg+": no known fix for "+singleLine(strings.Join(r.NoFix, ", ")))
		}
		if r.Upgrade != "" {
			anyVia = anyVia || r.Via != ""
			rows = append(rows, []string{pkg, singleLine(r.Upgrade), strconv.Itoa(len(r.Fixes)), viaCell(r.Via), singleLine(r.Manifest)})
		}
	}
	var lines []string
	if len(rows) > 1 {
		lines = append(lines, alignRows(rows, func(_, _ int, c string) string { return c })...)
	}
	lines = append(lines, notes...)
	if len(rows) > 1 {
		lines = append(lines, "Each upgrade is the lowest version at or above every known fix for that package. It can still break your build; check the release notes. Orbit does not check that the version exists or that no other advisory affects it.")
		if anyVia {
			lines = append(lines, "VIA is the direct dependency that pulls the package in: a newer release of it, or an override in your package manager, may be needed.")
		}
	}
	return lines
}

// viaCell shortens a long Via list for the table; JSON keeps it whole.
func viaCell(via string) string {
	if via == "" {
		return "-"
	}
	names := strings.Split(via, ", ")
	if len(names) > 3 {
		return singleLine(strings.Join(names[:3], ", ")) + fmt.Sprintf(" and %d more", len(names)-3)
	}
	return singleLine(via)
}

// licenseCell is a dependency's license for the table, "-" when unknown.
func licenseCell(d *entity.Dependency) string {
	if d.License == "" {
		return "-"
	}
	return d.License
}

// licensePolicyLine is the table's verdict line for the license policy. It
// counts the violations that are not ignored.
func licensePolicyLine(s Summary) string {
	n := 0
	for _, v := range s.LicenseViolations {
		if !v.Ignored {
			n++
		}
	}
	status := "passed"
	if s.LicenseFailed {
		status = "FAILED"
	}
	noun := "violations"
	if n == 1 {
		noun = "violation"
	}
	return fmt.Sprintf("license policy (deny %s): %d %s, %s", singleLine(strings.Join(s.DeniedLicenses, ", ")), n, noun, status)
}
