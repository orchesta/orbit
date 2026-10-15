package report

import (
	"strings"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
)

func TestParseIgnoreFile(t *testing.T) {
	in := `# comment

GHSA-xxxx-yyyy-zzzz  expires=2026-12-31  Not reachable: only used in tests
CVE-2024-1234        package=lodash     Accepted until upgrade, see JIRA-12
   cve-2024-9999   package=a expires=2026-01-02 see x=y in the reason
GHSA-bare
`
	l, err := ParseIgnoreFile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 4 {
		t.Fatalf("entries = %+v", l.Entries)
	}
	e := l.Entries[0]
	wantExp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) // end of 2026-12-31 UTC
	if e.ID != "GHSA-xxxx-yyyy-zzzz" || !e.Expires.Equal(wantExp) || e.Reason != "Not reachable: only used in tests" || e.Package != "" {
		t.Errorf("entry0 = %+v", e)
	}
	e = l.Entries[1]
	if e.ID != "CVE-2024-1234" || e.Package != "lodash" || !e.Expires.IsZero() || e.Reason != "Accepted until upgrade, see JIRA-12" {
		t.Errorf("entry1 = %+v", e)
	}
	e = l.Entries[2]
	if e.Package != "a" || e.Expires.IsZero() || e.Reason != "see x=y in the reason" {
		t.Errorf("entry2 = %+v", e)
	}
	if e := l.Entries[3]; e.ID != "GHSA-bare" || e.Reason != "" {
		t.Errorf("entry3 = %+v", e)
	}
}

func TestParseIgnoreFileErrors(t *testing.T) {
	cases := map[string]string{
		"bad date":      "# c\nGHSA-1 expires=2026-13-40 why",
		"bad date fmt":  "\n\nGHSA-1 expires=tomorrow why",
		"unknown key":   "GHSA-1\nGHSA-2 severity=high why",
		"empty package": "GHSA-1 package= why",
		"dup key":       "GHSA-1 package=a package=b why",
		"id is keyval":  "expires=2026-01-01 why",
	}
	wantLine := map[string]string{"bad date": "line 2", "bad date fmt": "line 3", "unknown key": "line 2",
		"empty package": "line 1", "dup key": "line 1", "id is keyval": "line 1"}
	for name, in := range cases {
		_, err := ParseIgnoreFile(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: expected error", name)
			continue
		}
		if !strings.Contains(err.Error(), wantLine[name]) {
			t.Errorf("%s: error %q lacks %q", name, err, wantLine[name])
		}
	}
}

func TestIgnoreExpiryEndOfDayUTC(t *testing.T) {
	l, err := ParseIgnoreFile(strings.NewReader("GHSA-1 expires=2026-10-15 r"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Match("GHSA-1", nil, "p", entity.EcosystemNpm, time.Date(2026, 10, 15, 23, 59, 59, 0, time.UTC)); !ok {
		t.Error("should still match on the expiry day")
	}
	if _, ok := l.Match("GHSA-1", nil, "p", entity.EcosystemNpm, time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)); ok {
		t.Error("should not match the day after")
	}
}

func TestIgnoreMatchCaseInsensitiveAliasAndPackage(t *testing.T) {
	l, err := ParseIgnoreFile(strings.NewReader("cve-2020-0001 package=lodash r1\nghsa-x r2"))
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := l.Match("GHSA-A", []string{"CVE-2020-0001"}, "lodash", entity.EcosystemNpm, fixedNow); !ok || r != "r1" {
		t.Errorf("alias match: %q %v", r, ok)
	}
	if _, ok := l.Match("GHSA-A", []string{"CVE-2020-0001"}, "other", entity.EcosystemNpm, fixedNow); ok {
		t.Error("package restriction ignored")
	}
	if r, ok := l.Match("GHSA-X", nil, "anything", entity.EcosystemNpm, fixedNow); !ok || r != "r2" {
		t.Errorf("case-insensitive id: %q %v", r, ok)
	}
}

func TestBuildIgnoreWarnings(t *testing.T) {
	l, err := ParseIgnoreFile(strings.NewReader(strings.Join([]string{
		"GHSA-low-0004 expires=2027-01-01 used",
		"GHSA-high-0002 expires=2026-10-01 old",
		"GHSA-nothing-0000 never matches",
		"GHSA-medium-0001 package=django wrong package",
		"GHSA-gone-0000 expires=2026-01-01 expired and unmatched",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	_, s := Build(fixtureResult(), l, entity.SeverityHigh, fixedNow)
	joined := strings.Join(s.Warnings, "\n")
	for _, want := range []string{
		"ignore entry GHSA-high-0002 expired on 2026-10-01",
		"ignore entry GHSA-gone-0000 expired on 2026-01-01",
		"unused ignore entry GHSA-nothing-0000",
		"unused ignore entry GHSA-medium-0001",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
	for _, bad := range []string{"unused ignore entry GHSA-low-0004", "unused ignore entry GHSA-high-0002", "unused ignore entry GHSA-gone-0000"} {
		if strings.Contains(joined, bad) {
			t.Errorf("unexpected warning %q", bad)
		}
	}
	for i := 1; i < len(s.Warnings); i++ {
		if s.Warnings[i-1] > s.Warnings[i] {
			t.Errorf("warnings not sorted: %v", s.Warnings)
		}
	}
}

func TestParseIgnoreFileBOM(t *testing.T) {
	for name, in := range map[string]string{
		"comment": "\ufeff# header\nGHSA-1 r",
		"id":      "\ufeffGHSA-1 package=a r",
	} {
		l, err := ParseIgnoreFile(strings.NewReader(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := 1
		if len(l.Entries) != want || l.Entries[0].ID != "GHSA-1" {
			t.Errorf("%s: entries = %+v", name, l.Entries)
		}
	}
}

func TestParseIgnoreFileCRLFTabsEmptyExpires(t *testing.T) {
	l, err := ParseIgnoreFile(strings.NewReader("# c\r\nGHSA-1\texpires=2026-12-31\tpackage=a\twhy it\tis\r\n\r\nGHSA-2\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 2 || l.Entries[0].Package != "a" || l.Entries[0].Reason != "why it is" || l.Entries[1].ID != "GHSA-2" || l.Entries[1].Reason != "" {
		t.Errorf("entries = %+v", l.Entries)
	}
	if _, err := ParseIgnoreFile(strings.NewReader("GHSA-1 expires= why")); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("empty expires: %v", err)
	}
}

func TestBuildPackageNameRulesPerEcosystem(t *testing.T) {
	cases := []struct {
		eco        entity.Ecosystem
		dep, entry string
		want       bool
	}{
		{entity.EcosystemPyPI, "django", "Django", true},
		{entity.EcosystemPyPI, "zope.interface", "Zope_Interface", true},
		{entity.EcosystemNuGet, "newtonsoft.json", "Newtonsoft.Json", true},
		{entity.EcosystemNpm, "lodash", "Lodash", false},
		{entity.EcosystemGo, "github.com/a/b", "github.com/A/b", false},
		{entity.EcosystemNpm, "lodash", "lodash", true},
	}
	for _, c := range cases {
		l := &IgnoreList{Entries: []IgnoreEntry{{ID: "X-1", Package: c.entry}}}
		if got := l.matchIndex("X-1", nil, c.dep, c.eco, fixedNow) >= 0; got != c.want {
			t.Errorf("%s %q vs %q: got %v want %v", c.eco, c.dep, c.entry, got, c.want)
		}
	}
}

func TestParseIgnoreFileClipsEchoedTokens(t *testing.T) {
	long := strings.Repeat("A", 500)
	for name, in := range map[string]string{
		"id is keyval": long + "=x why",
		"unknown key":  "GHSA-1 " + long + "=x why",
		"bad date":     "GHSA-1 expires=" + long + " why",
	} {
		_, err := ParseIgnoreFile(strings.NewReader(in))
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if strings.Contains(err.Error(), strings.Repeat("A", 65)) || !strings.Contains(err.Error(), strings.Repeat("A", 60)) {
			t.Errorf("%s: token not clipped to 64 characters: %d bytes: %.120s", name, len(err.Error()), err)
		}
	}
}
