package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/orchesta/orbit/internal/domain/entity"
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
		rows := [][]string{{"SEVERITY", "ID", "PACKAGE", "FIXED", "MANIFEST"}}
		for _, x := range f {
			sev := strings.ToUpper(string(x.Vulnerability.Severity))
			if x.Ignored {
				sev += " (ignored)"
			}
			fixed := fixedIn(x.Vulnerability)
			if fixed == "" {
				fixed = "-"
			}
			rows = append(rows, []string{sev, singleLine(x.Vulnerability.OSVID),
				singleLine(x.Dependency.Name + "@" + x.Dependency.CurrentVersion), singleLine(fixed),
				singleLine(x.Dependency.ManifestFile)})
		}
		widths := make([]int, 5)
		for _, r := range rows {
			for i, c := range r {
				if n := utf8.RuneCountInString(c); n > widths[i] {
					widths[i] = n
				}
			}
		}
		for ri, r := range rows {
			var line strings.Builder
			for i, c := range r {
				cell := c
				if i == 0 && ri > 0 && color && !f[ri-1].Ignored {
					cell = colorize(c, f[ri-1].Vulnerability.Severity)
				}
				line.WriteString(cell)
				if i < len(r)-1 {
					line.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)+2))
				}
			}
			printf("%s\n", line.String())
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
	printf("\n")
	if s.Threshold != "" {
		status := "passed"
		if s.Failed {
			status = "FAILED"
		}
		printf("threshold %s: %s\n", s.Threshold, status)
	}
	for _, msg := range s.Warnings {
		printf("warning: %s\n", singleLine(msg))
	}
	return err
}
