package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// fixtureBaselineJSON is a report from an older orbit on older versions:
//   - lodash GHSA-crit-0003 (another version) is still present;
//   - Django lists cve-2020-0002 as an alias, so django's GHSA-high-0002
//     (alias CVE-2020-0002) is the same issue (PEP 503 name, any ID case);
//   - GHSA-esc-0005 is on PyPI express, not npm express, so it does not match.
const fixtureBaselineJSON = `{
  "schema_version": 1,
  "tool": {"name": "orbit", "version": "1.0.0", "information_uri": ""},
  "summary": {"dependencies": 2},
  "recommendations": [],
  "findings": [
    {"id": "GHSA-crit-0003", "aliases": [], "package": "lodash", "version": "4.17.10", "ecosystem": "npm", "kev": false},
    {"id": "GHSA-other-9999", "aliases": ["cve-2020-0002"], "package": "Django", "version": "2.2.0", "ecosystem": "PyPI"},
    {"id": "GHSA-esc-0005", "aliases": [], "package": "express", "version": "4.18.2", "ecosystem": "PyPI"}
  ]
}`

func fixtureBaseline(t *testing.T) *Baseline {
	t.Helper()
	b, err := ParseBaseline([]byte(fixtureBaselineJSON))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseBaselineReadsToolAndFindings(t *testing.T) {
	b := fixtureBaseline(t)
	if b.ToolVersion != "1.0.0" || b.Len() != 3 {
		t.Errorf("tool version %q, %d findings; want 1.0.0, 3", b.ToolVersion, b.Len())
	}
}

func TestParseBaselineAcceptsUTF8BOM(t *testing.T) {
	b, err := ParseBaseline(append([]byte("\ufeff"), fixtureBaselineJSON...))
	if err != nil || b.Len() != 3 {
		t.Fatalf("BOM: %v, %+v", err, b)
	}
}

func TestParseBaselineErrors(t *testing.T) {
	utf16 := []byte{0xFF, 0xFE, '{', 0, '}', 0}
	cases := map[string]struct {
		data string
		want string
	}{
		"empty":          {"", "is empty"},
		"blank":          {" \n\t", "is empty"},
		"bom only":       {"\ufeff", "is empty"},
		"utf-16":         {string(utf16), "UTF-16"},
		"truncated":      {`{"schema_version": 1, "findings": [`, "not an orbit JSON report"},
		"array":          {`[]`, "not an orbit JSON report"},
		"trailing data":  {`{"schema_version": 1, "findings": []} {}`, "not an orbit JSON report"},
		"sarif":          {`{"version": "2.1.0", "runs": []}`, "no schema_version"},
		"newer schema":   {`{"schema_version": 2, "findings": []}`, "schema_version 2 is not supported"},
		"no findings":    {`{"schema_version": 1}`, "no findings array"},
		"null findings":  {`{"schema_version": 1, "findings": null}`, "no findings array"},
		"no package":     {`{"schema_version": 1, "findings": [{"id": "X-1", "ecosystem": "npm"}]}`, "finding 1"},
		"no id":          {`{"schema_version": 1, "findings": [{"package": "p", "ecosystem": "npm"}]}`, "finding 1"},
		"no ecosystem":   {`{"schema_version": 1, "findings": [{"id": "X-1", "package": "p"}]}`, "finding 1"},
		"string version": {`{"schema_version": "1", "findings": []}`, "not an orbit JSON report"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBaseline([]byte(c.data))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestBaselineContains(t *testing.T) {
	b, err := ParseBaseline([]byte(`{"schema_version": 1, "findings": [
	  {"id": "GHSA-aaaa", "aliases": ["CVE-2024-0001"], "package": "Django_Rest.Framework", "ecosystem": "PyPI"},
	  {"id": "GHSA-bbbb", "aliases": [], "package": "Newtonsoft.Json", "ecosystem": "NuGet"},
	  {"id": "GHSA-cccc", "aliases": [], "package": "lodash", "ecosystem": "npm"},
	  {"id": "GO-2024-0001", "aliases": [], "package": "github.com/Sirupsen/logrus", "ecosystem": "Go"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		eco     entity.Ecosystem
		pkg, id string
		aliases []string
		want    bool
	}{
		{"same id", entity.EcosystemNpm, "lodash", "GHSA-cccc", nil, true},
		{"id case", entity.EcosystemNpm, "lodash", "ghsa-cccc", nil, true},
		{"current id is a baseline alias", entity.EcosystemPyPI, "django-rest-framework", "CVE-2024-0001", nil, true},
		{"current alias is the baseline id", entity.EcosystemPyPI, "django-rest-framework", "CVE-2024-0001", []string{"ghsa-aaaa"}, true},
		{"pep 503 name", entity.EcosystemPyPI, "DJANGO-REST-FRAMEWORK", "GHSA-aaaa", nil, true},
		{"nuget name case", entity.EcosystemNuGet, "newtonsoft.json", "GHSA-bbbb", nil, true},
		{"npm name is exact", entity.EcosystemNpm, "Lodash", "GHSA-cccc", nil, false},
		{"go path is exact", entity.EcosystemGo, "github.com/sirupsen/logrus", "GO-2024-0001", nil, false},
		{"go path match", entity.EcosystemGo, "github.com/Sirupsen/logrus", "GO-2024-0001", nil, true},
		{"other ecosystem", entity.EcosystemPyPI, "lodash", "GHSA-cccc", nil, false},
		{"other package", entity.EcosystemNpm, "underscore", "GHSA-cccc", nil, false},
		{"other advisory", entity.EcosystemNpm, "lodash", "GHSA-dddd", []string{"CVE-2024-9999"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := b.Contains(c.eco, c.pkg, c.id, c.aliases); got != c.want {
				t.Errorf("Contains = %v, want %v", got, c.want)
			}
		})
	}
}

// An orbit before the alias merge wrote one finding per GitHub advisory; the
// merged finding is now reported under the CVE. osv.dev may also add an alias
// later. Either way the finding is not new.
func TestBaselineContainsAcrossAliasDrift(t *testing.T) {
	b, err := ParseBaseline([]byte(`{"schema_version": 1, "findings": [
	  {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "package": "lodash", "ecosystem": "npm"},
	  {"id": "GHSA-r5fr-rjxr-66jc", "aliases": [], "package": "lodash", "ecosystem": "npm"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !b.Contains(entity.EcosystemNpm, "lodash", "CVE-2021-23337", []string{"GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"}) {
		t.Error("merged finding under the CVE must match the two old GHSA findings")
	}
	if !b.Contains(entity.EcosystemNpm, "lodash", "CVE-2099-0001", []string{"GHSA-r5fr-rjxr-66jc"}) {
		t.Error("a finding whose primary ID changed must match through a shared alias")
	}
}

// Whatever WriteJSON writes, ParseBaseline reads back, and every finding of
// the report is in the resulting baseline.
func TestBaselineRoundTripsWriteJSON(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, f, s, testTool); err != nil {
		t.Fatal(err)
	}
	b, err := ParseBaseline(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if b.Len() != len(f) || b.ToolVersion != testTool.Version {
		t.Fatalf("Len = %d, ToolVersion = %q", b.Len(), b.ToolVersion)
	}
	for _, x := range f {
		if !b.Contains(x.Dependency.Ecosystem, x.Dependency.Name, x.Vulnerability.OSVID, x.Vulnerability.Aliases) {
			t.Errorf("%s on %s missing from its own baseline", x.Vulnerability.OSVID, x.Dependency.Name)
		}
	}
}
