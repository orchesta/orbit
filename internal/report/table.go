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

// WriteTable prints findings in severity order followed by a summary and
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
		header := []string{"SEVERITY", "ID", "PACKAGE", "FIXED", "MANIFEST"}
		if exploitCols {
			header = []string{"SEVERITY", "KEV", "EPSS", "ID", "PACKAGE", "FIXED", "MANIFEST"}
		}
		rows := [][]string{header}
		for _, x := range f {
			fixed := fixedIn(x.Vulnerability)
			if fixed == "" {
				fixed = "-"
			}
			row := []string{severityCell(x)}
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
				singleLine(x.Dependency.Name+"@"+x.Dependency.CurrentVersion), singleLine(fixed),
				singleLine(x.Dependency.ManifestFile))
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
	printf("\n")
	if s.KEVFindings > 0 {
		printf("%d known exploited (CISA KEV)\n", s.KEVFindings)
	}
	if s.Threshold != "" {
		// Only the severity and malicious gate: the KEV gate has its own
		// line below. The exit code follows s.Failed, which covers both.
		status := "passed"
		if s.ThresholdFailed {
			status = "FAILED"
		}
		printf("threshold %s: %s\n", s.Threshold, status)
	}
	if s.FailOnKEV {
		status := "passed"
		if s.KEVFailed {
			status = "FAILED"
		}
		printf("fail on KEV: %s\n", status)
	}
	for _, msg := range s.Warnings {
		printf("warning: %s\n", singleLine(msg))
	}
	return err
}

// severityCell is the SEVERITY column: the severity in capitals, followed by
// "(malicious)", "(ignored)" or both.
func severityCell(x Finding) string {
	sev := strings.ToUpper(string(x.Vulnerability.Severity))
	var marks []string
	if x.Malicious {
		marks = append(marks, "malicious")
	}
	if x.Ignored {
		marks = append(marks, "ignored")
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
