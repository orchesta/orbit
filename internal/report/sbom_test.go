package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

var sbomOpts = SBOMOptions{
	Name:   "web",
	Now:    fixedNow,
	Serial: uuid.MustParse("3e671687-395b-41f5-a30f-a58921a69b79"),
}

// sbomFixture covers every ecosystem, a package found in two manifests, a
// scoped npm name, a dev dependency, a transitive dependency, an unresolved
// range, valid and invalid licenses, an ignored finding, a known malicious
// package (reported under a CVE with the MAL- ID as an alias, and fixed in a
// later release) with two other advisories, one fixed and one not, and a
// reference that is not a URL.
func sbomFixture() *engine.Result {
	dep := func(n, v, eco, mf string, direct, dev, resolved bool, lic string) *entity.Dependency {
		return &entity.Dependency{ID: uuid.New(), Name: n, CurrentVersion: v, Ecosystem: entity.Ecosystem(eco),
			ManifestFile: mf, IsDirect: direct, IsDev: dev, IsResolved: resolved, License: lic}
	}
	lodashA := dep("lodash", "4.17.15", "npm", "package-lock.json", true, false, true, "MIT")
	lodashB := dep("lodash", "4.17.15", "npm", "web/package-lock.json", false, false, true, "")
	types := dep("@types/node", "20.1.0", "npm", "package-lock.json", true, true, true, "MIT")
	ms := dep("ms", "2.1.3", "npm", "package-lock.json", false, false, true, "SEE LICENSE IN LICENSE.md")
	django := dep("django", "3.0.0", "PyPI", "requirements.txt", true, false, true, "bsd-3-clause")
	toml := dep("github.com/BurntSushi/toml", "1.6.0", "Go", "go.mod", true, false, false, "LicenseRef-Toml")
	newtonsoft := dep("Newtonsoft.Json", "[13.0,14.0)", "NuGet", "app.csproj", true, false, false, "MIT OR Apache-2.0")
	vuln := func(d *entity.Dependency, id string, sev entity.Severity, fix *string, aliases, refs []string) *entity.Vulnerability {
		return &entity.Vulnerability{ID: uuid.New(), DependencyID: d.ID, OSVID: id, Aliases: aliases,
			Summary: id + " summary", Severity: sev, FixedVersion: fix, References: refs}
	}
	return &engine.Result{
		Dependencies: []*entity.Dependency{lodashA, lodashB, types, ms, django, toml, newtonsoft},
		Vulnerabilities: []*entity.Vulnerability{
			vuln(lodashA, "GHSA-lodash-0001", entity.SeverityHigh, strp("4.17.21"), []string{"CVE-2020-8203"},
				[]string{"https://github.com/advisories/GHSA-lodash-0001", "not a url"}),
			vuln(lodashB, "GHSA-lodash-0001", entity.SeverityHigh, strp("4.17.21"), []string{"CVE-2020-8203"}, nil),
			vuln(django, "GHSA-django-0002", entity.SeverityLow, strp("3.0.8"), nil, nil),
			vuln(toml, "GO-2026-0003", entity.SeverityUnknown, nil, nil, nil),
			vuln(ms, "CVE-2026-0004", entity.SeverityCritical, strp("2.1.4"), []string{"MAL-2026-0004"}, nil),
			vuln(ms, "GHSA-ms-0005", entity.SeverityMedium, strp("2.1.5"), nil, nil),
			vuln(ms, "GHSA-ms-0006", entity.SeverityLow, nil, nil, nil),
		},
	}
}

func buildSBOMFixture(t *testing.T) ([]Finding, Summary) {
	t.Helper()
	ignores := &IgnoreList{Entries: []IgnoreEntry{{ID: "GHSA-django-0002", Reason: "not reachable"}}}
	return Build(sbomFixture(), ignores, entity.SeverityHigh, fixedNow)
}

func TestCycloneDXGolden(t *testing.T) {
	f, s := buildSBOMFixture(t)
	var b bytes.Buffer
	if err := WriteCycloneDX(&b, f, s, testTool, sbomOpts); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.cdx.golden", b.Bytes())

	var doc struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
			Group  string `json:"group"`
			Name   string `json:"name"`
			PURL   string `json:"purl"`
			Scope  string `json:"scope"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
		Vulnerabilities []struct {
			ID             string `json:"id"`
			Recommendation string `json:"recommendation"`
			Analysis       *struct {
				State    string   `json:"state"`
				Response []string `json:"response"`
				Detail   string   `json:"detail"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 6 {
		t.Fatalf("components = %d, want 6 (lodash from two manifests is one)", len(doc.Components))
	}
	refs := map[string]bool{}
	for _, c := range doc.Components {
		if refs[c.BOMRef] {
			t.Errorf("duplicate bom-ref %s", c.BOMRef)
		}
		refs[c.BOMRef] = true
		if c.Name == "node" && (c.Group != "@types" || c.PURL != "pkg:npm/%40types/node@20.1.0" || c.Scope != "optional") {
			t.Errorf("scoped dev component = %+v", c)
		}
	}
	if got := doc.Dependencies[0].DependsOn; doc.Dependencies[0].Ref != "root" || len(got) != 5 {
		t.Errorf("root dependsOn = %v, want the 5 direct packages", got)
	}
	if len(doc.Vulnerabilities) != 6 {
		t.Fatalf("vulnerabilities = %d, want 6 (one per advisory and package)", len(doc.Vulnerabilities))
	}
	for _, v := range doc.Vulnerabilities {
		if !refs[v.Affects[0].Ref] {
			t.Errorf("%s affects unknown ref %s", v.ID, v.Affects[0].Ref)
		}
		// An ignored finding is an accepted risk, not a claim that the
		// component is unaffected.
		ignored := v.Analysis != nil && v.Analysis.State == "exploitable" &&
			slices.Equal(v.Analysis.Response, []string{"will_not_fix"}) &&
			v.Analysis.Detail == "Ignored in .orbitignore: not reachable"
		if ignored != (v.ID == "GHSA-django-0002") || (v.Analysis != nil && !ignored) {
			t.Errorf("%s analysis = %+v", v.ID, v.Analysis)
		}
	}
	// A malicious package is removed, not upgraded; it sorts first.
	if v := doc.Vulnerabilities[0]; v.ID != "CVE-2026-0004" ||
		v.Recommendation != "Remove or replace ms: it is a known malicious package (MAL-2026-0004) (fixed in 2.1.4)." {
		t.Errorf("malicious vulnerability = %s, recommendation %q", v.ID, v.Recommendation)
	}
	// The other advisories of a malicious package say so, as in SARIF.
	for _, v := range doc.Vulnerabilities {
		want := map[string]string{
			"GHSA-ms-0005": "Fixed in 2.1.5. This package is reported as malicious; remove or replace it.",
			"GHSA-ms-0006": "No fix available. This package is reported as malicious; remove or replace it.",
		}[v.ID]
		if want != "" && v.Recommendation != want {
			t.Errorf("%s: recommendation = %q, want %q", v.ID, v.Recommendation, want)
		}
	}
}

func TestCycloneDXRecommendation(t *testing.T) {
	ms := &sbomPackage{Ecosystem: entity.EcosystemNpm, Name: "ms", Version: "2.1.3"}
	toml := &sbomPackage{Ecosystem: entity.EcosystemGo, Name: "github.com/BurntSushi/toml", Version: "1.6.0"}
	for _, c := range []struct {
		x         Finding
		p         *sbomPackage
		malicious bool // the package has a malicious finding
		want      string
	}{
		{Finding{Malicious: true, Vulnerability: &entity.Vulnerability{OSVID: "MAL-2026-0005"}}, ms, true,
			"Remove or replace ms: it is a known malicious package (MAL-2026-0005)."},
		{Finding{Malicious: true, Vulnerability: &entity.Vulnerability{OSVID: "CVE-2026-0006",
			Aliases: []string{"GHSA-x", "MAL-2026-0006"}, FixedVersion: strp("2.1.4")}}, ms, true,
			"Remove or replace ms: it is a known malicious package (MAL-2026-0006) (fixed in 2.1.4)."},
		{Finding{Vulnerability: &entity.Vulnerability{OSVID: "GHSA-ms-0009", FixedVersion: strp("2.1.5")}}, ms, true,
			"Fixed in 2.1.5" + removalHint},
		{Finding{Vulnerability: &entity.Vulnerability{OSVID: "GHSA-ms-0010"}}, ms, true,
			"No fix available" + removalHint},
		{Finding{Vulnerability: &entity.Vulnerability{OSVID: "GO-2026-0007", FixedVersion: strp("1.6.1")}}, toml, false,
			"Upgrade github.com/BurntSushi/toml to v1.6.1."},
		{Finding{Vulnerability: &entity.Vulnerability{OSVID: "GO-2026-0008"}}, toml, false, ""},
	} {
		if got := cdxRecommendation(c.x, c.p, c.malicious); got != c.want {
			t.Errorf("%s: recommendation = %q, want %q", c.x.Vulnerability.OSVID, got, c.want)
		}
	}
}

// writeCDX writes findings f for deps and decodes the vulnerabilities.
func writeCDX(t *testing.T, deps []*entity.Dependency, f []Finding) []cdxVulnerability {
	t.Helper()
	var b bytes.Buffer
	if err := WriteCycloneDX(&b, f, Summary{Deps: deps}, testTool, sbomOpts); err != nil {
		t.Fatal(err)
	}
	validateSchema(t, "bom-1.6.schema.json", b.Bytes())
	var doc struct {
		Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Vulnerabilities
}

// One component found in two manifests is ignored only if every finding
// of the advisory on it is, whatever the finding order.
func TestCycloneDXIgnoredOnlyIfEveryFindingIs(t *testing.T) {
	a := &entity.Dependency{ID: uuid.New(), Name: "lodash", CurrentVersion: "4.17.15", Ecosystem: entity.EcosystemNpm,
		ManifestFile: "a/package-lock.json", IsDirect: true, IsResolved: true}
	b := &entity.Dependency{ID: uuid.New(), Name: "lodash", CurrentVersion: "4.17.15", Ecosystem: entity.EcosystemNpm,
		ManifestFile: "b/package-lock.json", IsDirect: true, IsResolved: true}
	va := &entity.Vulnerability{OSVID: "GHSA-lodash-0001", DependencyID: a.ID, Severity: entity.SeverityHigh}
	vb := &entity.Vulnerability{OSVID: "GHSA-lodash-0001", DependencyID: b.ID, Severity: entity.SeverityHigh}
	ignoredA := Finding{Dependency: a, Vulnerability: va, Ignored: true, IgnoreReason: "only in a"}
	ignoredB := Finding{Dependency: b, Vulnerability: vb, Ignored: true, IgnoreReason: "only in b"}
	for name, c := range map[string]struct {
		f       []Finding
		ignored bool
	}{
		"ignored first":  {[]Finding{ignoredA, {Dependency: b, Vulnerability: vb}}, false},
		"ignored second": {[]Finding{{Dependency: a, Vulnerability: va}, ignoredB}, false},
		"both ignored":   {[]Finding{ignoredA, ignoredB}, true},
	} {
		vs := writeCDX(t, []*entity.Dependency{a, b}, c.f)
		if len(vs) != 1 {
			t.Fatalf("%s: vulnerabilities = %d, want 1", name, len(vs))
		}
		if got := vs[0].Analysis != nil; got != c.ignored {
			t.Errorf("%s: analysis = %+v, want ignored %v", name, vs[0].Analysis, c.ignored)
		}
	}
}

// Only a concrete installed version is listed as affected: a declared
// range is not a version.
func TestCycloneDXAffectsOnlyExactVersions(t *testing.T) {
	for _, c := range []struct {
		eco     entity.Ecosystem
		name    string
		version string
		want    []cdxAffectedVersion
	}{
		{entity.EcosystemNuGet, "Newtonsoft.Json", "[13.0,14.0)", []cdxAffectedVersion{{"13.0.2", "unaffected"}}},
		{entity.EcosystemNpm, "left-pad", "^1.0.0", []cdxAffectedVersion{{"13.0.2", "unaffected"}}},
		{entity.EcosystemNpm, "left-pad", "1.3.0", []cdxAffectedVersion{{"1.3.0", "affected"}, {"13.0.2", "unaffected"}}},
		{entity.EcosystemGo, "golang.org/x/mod", "0.42.0", []cdxAffectedVersion{{"v0.42.0", "affected"}, {"v13.0.2", "unaffected"}}},
		{entity.EcosystemGo, "golang.org/x/mod", "v0.42.0", []cdxAffectedVersion{{"v0.42.0", "affected"}, {"v13.0.2", "unaffected"}}},
	} {
		d := &entity.Dependency{ID: uuid.New(), Name: c.name, CurrentVersion: c.version, Ecosystem: c.eco, IsDirect: true}
		v := &entity.Vulnerability{OSVID: "GHSA-x", DependencyID: d.ID, FixedVersion: strp("13.0.2")}
		vs := writeCDX(t, []*entity.Dependency{d}, []Finding{{Dependency: d, Vulnerability: v}})
		if got := vs[0].Affects[0].Versions; !slices.Equal(got, c.want) {
			t.Errorf("%s %s: versions = %+v, want %+v", c.name, c.version, got, c.want)
		}
	}
}

func TestWebURL(t *testing.T) {
	for s, want := range map[string]bool{
		"https://github.com/advisories/GHSA-x": true,
		"http://example.com/a?b=c#d":           true,
		"not a url":                            false,
		"ftp://example.com/x":                  false,
		"https://":                             false,
		"/relative/path":                       false,
		`https://a.com/a\b`:                    false,
		"https://a.com/<x>":                    false,
		`https://a.com/"x"`:                    false,
		"https://a.com/{x}":                    false,
		"https://a.com/a|b":                    false,
		"https://a.com/a^b":                    false,
		"https://a.com/a`b":                    false,
		"https://a.com/a b":                    false,
	} {
		if got := webURL(s); got != want {
			t.Errorf("webURL(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestCycloneDXEmpty(t *testing.T) {
	f, s := Build(&engine.Result{}, nil, "", fixedNow)
	var b bytes.Buffer
	if err := WriteCycloneDX(&b, f, s, testTool, SBOMOptions{Now: fixedNow, Serial: sbomOpts.Serial}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"components": []`, `"vulnerabilities": []`, `"dependsOn": []`, `"name": "unnamed"`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("want %s in:\n%s", want, b.String())
		}
	}
	validateSchema(t, "bom-1.6.schema.json", b.Bytes())
}

func TestSBOMPackagesMergeByEcosystemRules(t *testing.T) {
	dep := func(eco entity.Ecosystem, name, version string, direct, dev bool) *entity.Dependency {
		return &entity.Dependency{ID: uuid.New(), Name: name, CurrentVersion: version, Ecosystem: eco,
			ManifestFile: string(eco) + ".lock", IsDirect: direct, IsDev: dev}
	}
	deps := []*entity.Dependency{
		dep(entity.EcosystemNuGet, "Newtonsoft.Json", "13.0.1", true, true),
		dep(entity.EcosystemNuGet, "newtonsoft.json", "13.0.1", false, false),
		dep(entity.EcosystemPyPI, "zope.interface", "5.4.0", true, false),
		dep(entity.EcosystemPyPI, "Zope_Interface", "5.4.0", true, false),
		dep(entity.EcosystemNpm, "JSONStream", "1.3.5", true, false),
		dep(entity.EcosystemNpm, "jsonstream", "1.3.5", true, false),
		dep(entity.EcosystemGo, "golang.org/x/mod", "0.42.0", true, false),
		dep(entity.EcosystemGo, "golang.org/x/mod", "v0.42.0", true, false),
		dep(entity.EcosystemNpm, "left-pad", "^1.0.0", true, false),
		dep(entity.EcosystemNpm, "left-pad", ">=1.0.0 <2", true, false),
	}
	pkgs, byDep := sbomPackages(deps)
	if len(pkgs) != 7 {
		for _, p := range pkgs {
			t.Log(p.Ref)
		}
		t.Fatalf("packages = %d, want 7 (NuGet, PyPI and Go pairs merge; npm names are case-sensitive; two ranges stay two)", len(pkgs))
	}
	refs := map[string]bool{}
	for _, p := range pkgs {
		if refs[p.Ref] {
			t.Errorf("duplicate bom-ref %s", p.Ref)
		}
		refs[p.Ref] = true
	}
	nuget := byDep[deps[0].ID]
	if nuget != byDep[deps[1].ID] || !nuget.Direct || nuget.Dev || nuget.Name != "Newtonsoft.Json" {
		t.Errorf("NuGet pair = %+v: want one direct, non-dev package named as first seen", nuget)
	}
	if byDep[deps[2].ID] != byDep[deps[3].ID] || byDep[deps[2].ID].PURL != "pkg:pypi/zope.interface@5.4.0" {
		t.Errorf("PyPI pair = %+v", byDep[deps[2].ID])
	}
	if byDep[deps[6].ID] != byDep[deps[7].ID] {
		t.Error(`Go "0.42.0" and "v0.42.0" must be one package`)
	}
	if p := byDep[deps[8].ID]; p.PURL != "pkg:npm/left-pad" || p.Ref == byDep[deps[9].ID].Ref {
		t.Errorf("ranges: purl %s, refs %s / %s", p.PURL, p.Ref, byDep[deps[9].ID].Ref)
	}
}

// Names that used to collapse into one purl (slashes were trimmed) must keep
// distinct bom-refs, whatever their sbomKey.
func TestSBOMPackagesRefsStayUnique(t *testing.T) {
	var deps []*entity.Dependency
	for _, eco := range []entity.Ecosystem{entity.EcosystemNpm, entity.EcosystemPyPI, entity.EcosystemNuGet, entity.EcosystemGo} {
		for _, name := range []string{"a/b", "/a/b", "a/b/", "a//b", "/", "//", "@a/b", "/@a/b", "a", "A", "..", "a?b", "a%3Fb", "Keras", "Keras"} {
			for _, v := range []string{"1.0.0", "latest", "1.x", "^1.0"} {
				deps = append(deps, &entity.Dependency{ID: uuid.New(), Name: name, CurrentVersion: v, Ecosystem: eco})
			}
		}
	}
	pkgs, _ := sbomPackages(deps)
	refs := map[string]bool{}
	for _, p := range pkgs {
		if refs[p.Ref] {
			t.Errorf("duplicate bom-ref %s", p.Ref)
		}
		refs[p.Ref] = true
	}
}

func TestSPDXGolden(t *testing.T) {
	f, s := buildSBOMFixture(t)
	var b bytes.Buffer
	if err := WriteSPDX(&b, f, s, testTool, sbomOpts); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.spdx.golden", b.Bytes())

	var doc struct {
		DocumentNamespace string `json:"documentNamespace"`
		Packages          []struct {
			SPDXID          string `json:"SPDXID"`
			Name            string `json:"name"`
			LicenseDeclared string `json:"licenseDeclared"`
			Supplier        string `json:"supplier"`
			CopyrightText   string `json:"copyrightText"`
		} `json:"packages"`
		Relationships []struct {
			From string `json:"spdxElementId"`
			Type string `json:"relationshipType"`
			To   string `json:"relatedSpdxElement"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.DocumentNamespace != "https://example.com/orbit/spdx/web-3e671687-395b-41f5-a30f-a58921a69b79" {
		t.Errorf("documentNamespace = %s", doc.DocumentNamespace)
	}
	if len(doc.Packages) != 7 { // root + 6
		t.Fatalf("packages = %d, want 7", len(doc.Packages))
	}
	for _, p := range doc.Packages {
		if p.Name == "ms" && p.LicenseDeclared != "NOASSERTION" {
			t.Errorf("an invalid license expression must become NOASSERTION, got %q", p.LicenseDeclared)
		}
		// orbit does not know who supplied a package or its copyright, the
		// project's own included.
		if p.Supplier != "NOASSERTION" || p.CopyrightText != "NOASSERTION" {
			t.Errorf("%s: supplier %q, copyrightText %q, want NOASSERTION", p.SPDXID, p.Supplier, p.CopyrightText)
		}
	}
	count := map[string]int{}
	for _, r := range doc.Relationships {
		count[r.Type]++
	}
	if count["DESCRIBES"] != 1 || count["DEPENDS_ON"] != 4 || count["DEV_DEPENDENCY_OF"] != 1 {
		t.Errorf("relationships = %v", count)
	}
	if strings.Contains(b.String(), "GHSA-") || strings.Contains(b.String(), "MAL-") {
		t.Error("SPDX 2.3 output must not contain vulnerabilities")
	}
}

// Names that sanitise to one identifier, or to one already suffixed, and
// names with characters an SPDXID cannot hold must still give valid, unique
// identifiers that every relationship can resolve.
func TestSPDXIDsStayValidAndUnique(t *testing.T) {
	dep := func(eco entity.Ecosystem, name, version string, direct, dev bool) *entity.Dependency {
		return &entity.Dependency{ID: uuid.New(), Name: name, CurrentVersion: version, Ecosystem: eco,
			ManifestFile: "lock", IsDirect: direct, IsDev: dev}
	}
	deps := []*entity.Dependency{
		dep(entity.EcosystemNpm, "a_b", "1.0.0", true, false),
		dep(entity.EcosystemNpm, "a b", "1.0.0", true, true),
		dep(entity.EcosystemNpm, "a-b", "1.0.0", true, false),
		dep(entity.EcosystemNpm, "a-b", "1.0.0-2", true, false),
		dep(entity.EcosystemNpm, "çağrı-日本", "1.0.0", true, false),
		dep(entity.EcosystemNpm, "##[error]x", "1.0.0", true, true),
		dep(entity.EcosystemGo, "github.com/Sirupsen/logrus", "v1.9.0", true, false),
		dep(entity.EcosystemGo, "github.com/sirupsen/logrus", "v1.9.0", true, false),
		dep(entity.EcosystemNpm, "transitive", "1.0.0", false, false),
	}
	var b bytes.Buffer
	if err := WriteSPDX(&b, nil, Summary{Deps: deps}, testTool, sbomOpts); err != nil {
		t.Fatal(err)
	}
	validateSchema(t, "spdx-2.3.schema.json", b.Bytes())
	var doc struct {
		Packages []struct {
			SPDXID string `json:"SPDXID"`
		} `json:"packages"`
		Relationships []struct {
			From string `json:"spdxElementId"`
			To   string `json:"relatedSpdxElement"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Packages) != len(deps)+1 {
		t.Fatalf("packages = %d, want %d (root + one per dependency)", len(doc.Packages), len(deps)+1)
	}
	valid := regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)
	ids := map[string]bool{"SPDXRef-DOCUMENT": true}
	for _, p := range doc.Packages {
		if !valid.MatchString(p.SPDXID) {
			t.Errorf("SPDXID %q is not valid", p.SPDXID)
		}
		if ids[p.SPDXID] {
			t.Errorf("duplicate SPDXID %q", p.SPDXID)
		}
		ids[p.SPDXID] = true
	}
	if len(doc.Relationships) != len(deps) { // DESCRIBES + one per direct dependency
		t.Errorf("relationships = %d, want %d", len(doc.Relationships), len(deps))
	}
	for _, r := range doc.Relationships {
		if !ids[r.From] || !ids[r.To] {
			t.Errorf("relationship %s -> %s refers to an unknown SPDXID", r.From, r.To)
		}
	}
}

func TestSBOMNeutralisesCICommands(t *testing.T) {
	res := &engine.Result{Dependencies: []*entity.Dependency{{ID: uuid.New(), Name: "##vso[task.setvariable]x",
		CurrentVersion: "1.0.0", Ecosystem: entity.EcosystemNpm, ManifestFile: "package-lock.json", IsDirect: true}}}
	f, s := Build(res, nil, "", fixedNow)
	for name, write := range map[string]func(*bytes.Buffer) error{
		"cyclonedx": func(b *bytes.Buffer) error { return WriteCycloneDX(b, f, s, testTool, sbomOpts) },
		"spdx":      func(b *bytes.Buffer) error { return WriteSPDX(b, f, s, testTool, sbomOpts) },
	} {
		var b bytes.Buffer
		if err := write(&b); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), "##vso[") {
			t.Errorf("%s: raw ##vso[ in output", name)
		}
	}
}
