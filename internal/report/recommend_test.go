package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

func rdep(name, version, eco, manifest string, via ...string) *entity.Dependency {
	return &entity.Dependency{ID: uuid.New(), Name: name, CurrentVersion: version, Ecosystem: entity.Ecosystem(eco),
		ManifestFile: manifest, IsResolved: true, Via: via}
}

func rvuln(d *entity.Dependency, id string, sev entity.Severity, fix string) *entity.Vulnerability {
	v := &entity.Vulnerability{ID: uuid.New(), DependencyID: d.ID, OSVID: id, Severity: sev}
	if fix != "" {
		v.FixedVersion = &fix
	}
	return v
}

func recs(t *testing.T, deps []*entity.Dependency, vulns []*entity.Vulnerability, ignores *IgnoreList) []Recommendation {
	t.Helper()
	_, s := Build(&engine.Result{Dependencies: deps, Vulnerabilities: vulns}, ignores, "", fixedNow)
	return s.Recommendations
}

func TestRecommendTakesTheHighestFixAndNamesAdvisoriesWithoutOne(t *testing.T) {
	lodash := rdep("lodash", "4.17.15", "npm", "package-lock.json")
	got := recs(t, []*entity.Dependency{lodash}, []*entity.Vulnerability{
		rvuln(lodash, "GHSA-a", entity.SeverityHigh, "4.17.19"),
		rvuln(lodash, "GHSA-b", entity.SeverityMedium, "4.17.21"),
		rvuln(lodash, "GHSA-c", entity.SeverityLow, "4.17.12"), // stale: not above the installed version
		rvuln(lodash, "GHSA-d", entity.SeverityCritical, ""),
	}, nil)
	want := []Recommendation{{
		Ecosystem: "npm", Package: "lodash", Current: "4.17.15", Upgrade: "4.17.21",
		Fixes: []string{"GHSA-a", "GHSA-b"}, NoFix: []string{"GHSA-c", "GHSA-d"}, Manifest: "package-lock.json",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestRecommendComparesVersionsPerEcosystem(t *testing.T) {
	django := rdep("django", "3.0.0", "PyPI", "poetry.lock")
	next := rdep("next", "13.0.0", "npm", "package-lock.json")
	pillow := rdep("pillow", "9.0.0", "PyPI", "poetry.lock")
	newtonsoft := rdep("Newtonsoft.Json", "12.0.1", "NuGet", "packages.lock.json")
	got := recs(t, []*entity.Dependency{django, next, pillow, newtonsoft}, []*entity.Vulnerability{
		rvuln(django, "GHSA-d1", entity.SeverityHigh, "3.0.7"),
		rvuln(django, "GHSA-d2", entity.SeverityHigh, "3.0.10"), // below "3.0.7" as a string
		rvuln(next, "GHSA-n1", entity.SeverityHigh, "13.5.0-canary.3"),
		rvuln(next, "GHSA-n2", entity.SeverityHigh, "13.5.0"),
		rvuln(pillow, "GHSA-p1", entity.SeverityHigh, "9.0.1rc1"),
		rvuln(pillow, "GHSA-p2", entity.SeverityHigh, "9.0.1"),
		rvuln(newtonsoft, "GHSA-j1", entity.SeverityHigh, "13.0.1"),
		rvuln(newtonsoft, "GHSA-j2", entity.SeverityHigh, "12.0.3.1"),
	}, nil)
	upgrades := map[string]string{}
	for _, r := range got {
		upgrades[r.Package] = r.Upgrade
	}
	want := map[string]string{"django": "3.0.10", "next": "13.5.0", "pillow": "9.0.1", "Newtonsoft.Json": "13.0.1"}
	if !reflect.DeepEqual(upgrades, want) {
		t.Fatalf("upgrades = %v, want %v", upgrades, want)
	}
}

func TestRecommendKeepsAFixWhenTheInstalledVersionIsARange(t *testing.T) {
	pad := rdep("left-pad", ">=1.0.0 <2", "npm", "package.json")
	got := recs(t, []*entity.Dependency{pad}, []*entity.Vulnerability{rvuln(pad, "GHSA-lp", entity.SeverityLow, "1.3.0")}, nil)
	if len(got) != 1 || got[0].Upgrade != "1.3.0" {
		t.Fatalf("got %+v, want an upgrade to 1.3.0", got)
	}
}

func TestRecommendKeepsEachInstalledVersionApart(t *testing.T) {
	direct := rdep("ms", "2.1.3", "npm", "package-lock.json")
	nested := rdep("ms", "2.0.0", "npm", "package-lock.json", "express", "mocha")
	got := recs(t, []*entity.Dependency{direct, nested}, []*entity.Vulnerability{
		rvuln(direct, "GHSA-ms-1", entity.SeverityMedium, "2.1.4"),
		rvuln(nested, "GHSA-ms-1", entity.SeverityMedium, "2.0.1"),
	}, nil)
	if len(got) != 2 {
		t.Fatalf("got %d recommendations, want one per installed version: %+v", len(got), got)
	}
	if got[0].Current != "2.0.0" || got[0].Upgrade != "2.0.1" || got[0].Via != "express, mocha" ||
		got[1].Current != "2.1.3" || got[1].Upgrade != "2.1.4" || got[1].Via != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestRecommendLeavesOutIgnoredFindings(t *testing.T) {
	qs := rdep("qs", "6.7.0", "npm", "package-lock.json")
	vulns := []*entity.Vulnerability{
		rvuln(qs, "GHSA-q1", entity.SeverityHigh, "6.7.3"),
		rvuln(qs, "GHSA-q2", entity.SeverityLow, "6.10.3"),
	}
	got := recs(t, []*entity.Dependency{qs}, vulns, &IgnoreList{Entries: []IgnoreEntry{{ID: "GHSA-q2", Reason: "accepted"}}})
	if len(got) != 1 || got[0].Upgrade != "6.7.3" || !slices.Equal(got[0].Fixes, []string{"GHSA-q1"}) {
		t.Fatalf("got %+v, want only GHSA-q1 fixed by 6.7.3", got)
	}
	got = recs(t, []*entity.Dependency{qs}, vulns, &IgnoreList{Entries: []IgnoreEntry{{ID: "GHSA-q1"}, {ID: "GHSA-q2"}}})
	if len(got) != 0 {
		t.Fatalf("got %+v, want none when every finding is ignored", got)
	}
}

func TestRecommendGivesGoUpgradesTheirV(t *testing.T) {
	net := rdep("golang.org/x/net", "v0.10.0", "Go", "go.mod")
	got := recs(t, []*entity.Dependency{net}, []*entity.Vulnerability{rvuln(net, "GO-2023-2102", entity.SeverityHigh, "0.17.0")}, nil)
	if len(got) != 1 || got[0].Upgrade != "v0.17.0" {
		t.Fatalf("got %+v, want v0.17.0", got)
	}
}

func TestRecommendFlagsMaliciousPackages(t *testing.T) {
	evil := rdep("evil-pkg", "1.0.0", "npm", "package-lock.json")
	got := recs(t, []*entity.Dependency{evil}, []*entity.Vulnerability{rvuln(evil, "MAL-2025-1234", entity.SeverityCritical, "")}, nil)
	if len(got) != 1 || !got[0].Malicious || got[0].Upgrade != "" || !slices.Equal(got[0].NoFix, []string{"MAL-2025-1234"}) {
		t.Fatalf("got %+v, want a malicious package with no upgrade", got)
	}
}

// debugAdvisories are debug@4.4.2 as Lookup reports it (osv.dev, October
// 2026): the GitHub advisory, fixed in 4.4.3, and the unscored MAL- record,
// both under CVE-2025-59144.
func debugAdvisories(debug *entity.Dependency) []*entity.Vulnerability {
	gh := rvuln(debug, "CVE-2025-59144", entity.SeverityHigh, "4.4.3")
	gh.Aliases = []string{"GHSA-4x49-vf9v-38px", "GHSA-8mgj-vmr8-frr6", "MAL-2025-46974"}
	mal := rvuln(debug, "CVE-2025-59144", entity.SeverityCritical, "")
	mal.Aliases = []string{"MAL-2025-46974", "GHSA-4x49-vf9v-38px", "GHSA-8mgj-vmr8-frr6"}
	return []*entity.Vulnerability{gh, mal}
}

// The merged finding keeps the GitHub fix (plan 01): the package is still to
// be removed, and the fixed version is kept so the outputs can name it.
func TestRecommendRemovesAMaliciousPackageAndNamesTheFix(t *testing.T) {
	debug := rdep("debug", "4.4.2", "npm", "package-lock.json")
	got := recs(t, []*entity.Dependency{debug}, debugAdvisories(debug), nil)
	if len(got) != 1 || !got[0].Malicious || got[0].Upgrade != "4.4.3" || !slices.Equal(got[0].Fixes, []string{"CVE-2025-59144"}) {
		t.Fatalf("got %+v, want a malicious package whose non-malicious advisory names 4.4.3", got)
	}
}

// The server stores one row per advisory: two rows for one CVE are merged
// before the upgrade is chosen, as in the CLI.
func TestRecommendForMergesAdvisoriesStoredTwice(t *testing.T) {
	lodash := rdep("lodash", "4.17.15", "npm", "package-lock.json")
	a := rvuln(lodash, "CVE-2021-23337", entity.SeverityHigh, "4.17.21")
	a.Aliases = []string{"GHSA-35jh-r3h4-6jhm"}
	b := rvuln(lodash, "CVE-2021-23337", entity.SeverityHigh, "4.18.0")
	b.Aliases = []string{"GHSA-r5fr-rjxr-66jc"}
	got := RecommendFor([]*entity.Dependency{lodash}, []*entity.Vulnerability{a, b})
	if len(got) != 1 || got[0].Upgrade != "4.18.0" || !slices.Equal(got[0].Fixes, []string{"CVE-2021-23337"}) {
		t.Fatalf("got %+v", got)
	}
	if got := RecommendFor(nil, nil); got == nil || len(got) != 0 {
		t.Fatalf("RecommendFor(nil, nil) = %#v, want an empty, non-nil list", got)
	}
}

func TestTableRecommendationsShowViaAndMalicious(t *testing.T) {
	qs := rdep("qs", "6.7.0", "npm", "package-lock.json", "body-parser", "express", "mocha", "webpack")
	evil := rdep("evil-pkg", "1.0.0", "npm", "package-lock.json")
	f, s := Build(&engine.Result{Dependencies: []*entity.Dependency{qs, evil}, Vulnerabilities: []*entity.Vulnerability{
		rvuln(qs, "CVE-2022-24999", entity.SeverityHigh, "6.7.3"),
		rvuln(evil, "MAL-2025-1234", entity.SeverityCritical, ""),
	}}, nil, "", fixedNow)
	var b bytes.Buffer
	if err := WriteTable(&b, f, s); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"qs@6.7.0  6.7.3       1      body-parser, express, mocha and 1 more  package-lock.json\n",
		"remove evil-pkg@1.0.0: reported as malicious (MAL-2025-1234)\n",
		"It can still break your build; check the release notes.\n",
		"VIA is the direct dependency that pulls the package in",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if regexp.MustCompile(`(?m)^evil-pkg@`).MatchString(out) {
		t.Errorf("a malicious package must not get an upgrade row:\n%s", out)
	}

	// debug@4.4.2: removal is still the advice; the GitHub fix is only named.
	debug := rdep("debug", "4.4.2", "npm", "package-lock.json")
	f, s = Build(&engine.Result{Dependencies: []*entity.Dependency{debug}, Vulnerabilities: debugAdvisories(debug)}, nil, "", fixedNow)
	b.Reset()
	if err := WriteTable(&b, f, s); err != nil {
		t.Fatal(err)
	}
	out = b.String()
	if want := "remove debug@4.4.2: reported as malicious (CVE-2025-59144); a non-malicious advisory names 4.4.3 as fixed\n"; !strings.Contains(out, want) {
		t.Errorf("missing %q in:\n%s", want, out)
	}
	if regexp.MustCompile(`(?m)^debug@4\.4\.2\s+4\.4\.3`).MatchString(out) {
		t.Errorf("a malicious package must not get an upgrade row:\n%s", out)
	}
}

// Two members of one group that differ only in how the fix is spelled
// ("2.0" and "2.0.0" are equal, so newer never switches) give the same
// merged fix whatever the input order.
func TestRecommendIsDeterministicWhenFixesAreSpelledDifferently(t *testing.T) {
	pkg := rdep("pkg", "1.0", "PyPI", "poetry.lock")
	a := rvuln(pkg, "CVE-2026-0001", entity.SeverityHigh, "2.0")
	b := rvuln(pkg, "CVE-2026-0001", entity.SeverityHigh, "2.0.0")
	var upgrades, fixes []string
	for _, vulns := range [][]*entity.Vulnerability{{a, b}, {b, a}} {
		f, s := Build(&engine.Result{Dependencies: []*entity.Dependency{pkg}, Vulnerabilities: vulns}, nil, "", fixedNow)
		if len(f) != 1 || len(s.Recommendations) != 1 {
			t.Fatalf("got %d findings, %d recommendations, want one of each", len(f), len(s.Recommendations))
		}
		fixes = append(fixes, fixedIn(f[0].Vulnerability))
		upgrades = append(upgrades, s.Recommendations[0].Upgrade)
	}
	if fixes[0] != fixes[1] || upgrades[0] != upgrades[1] {
		t.Fatalf("fixed versions %q and upgrades %q depend on input order", fixes, upgrades)
	}
}

func TestRecommendKeepsTheVOfAGoFix(t *testing.T) {
	net := rdep("golang.org/x/net", "v0.10.0", "Go", "go.mod")
	got := recs(t, []*entity.Dependency{net}, []*entity.Vulnerability{rvuln(net, "GO-2023-2102", entity.SeverityHigh, "v0.17.0")}, nil)
	if len(got) != 1 || got[0].Upgrade != "v0.17.0" {
		t.Fatalf("got %+v, want v0.17.0", got)
	}
}

// A malicious finding is never ignored, so an ignore entry does not hide
// its recommendation.
func TestRecommendKeepsAnIgnoredMaliciousPackage(t *testing.T) {
	evil := rdep("evil-pkg", "1.0.0", "npm", "package-lock.json")
	got := recs(t, []*entity.Dependency{evil}, []*entity.Vulnerability{rvuln(evil, "MAL-2025-1234", entity.SeverityCritical, "")},
		&IgnoreList{Entries: []IgnoreEntry{{ID: "MAL-2025-1234", Reason: "accepted"}}})
	if len(got) != 1 || !got[0].Malicious {
		t.Fatalf("got %+v, want the malicious package recommended", got)
	}
}

func TestRecommendSortsByTheMostSevereAdvisoryFirst(t *testing.T) {
	aaa := rdep("aaa", "1.0.0", "npm", "package-lock.json")
	mmm := rdep("mmm", "1.0.0", "npm", "package-lock.json")
	zzz := rdep("zzz", "1.0.0", "npm", "package-lock.json")
	got := recs(t, []*entity.Dependency{aaa, mmm, zzz}, []*entity.Vulnerability{
		rvuln(aaa, "GHSA-a", entity.SeverityLow, "1.0.1"),
		rvuln(mmm, "GHSA-m1", entity.SeverityLow, "1.0.1"),
		rvuln(mmm, "GHSA-m2", entity.SeverityHigh, "1.0.2"),
		rvuln(zzz, "GHSA-z", entity.SeverityCritical, "1.0.1"),
	}, nil)
	var order []string
	for _, r := range got {
		order = append(order, r.Package)
	}
	if want := []string{"zzz", "mmm", "aaa"}; !slices.Equal(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

// Two copies of one installed version (the same key, two dependency rows)
// list each advisory once.
func TestRecommendListsEachAdvisoryOnce(t *testing.T) {
	one := rdep("qs", "6.7.0", "npm", "package-lock.json")
	two := rdep("qs", "6.7.0", "npm", "package-lock.json")
	got := recs(t, []*entity.Dependency{one, two}, []*entity.Vulnerability{
		rvuln(one, "GHSA-q1", entity.SeverityHigh, "6.7.3"),
		rvuln(two, "GHSA-q1", entity.SeverityHigh, "6.7.3"),
		rvuln(one, "GHSA-q2", entity.SeverityLow, ""),
		rvuln(two, "GHSA-q2", entity.SeverityLow, ""),
	}, nil)
	if len(got) != 1 || !slices.Equal(got[0].Fixes, []string{"GHSA-q1"}) || !slices.Equal(got[0].NoFix, []string{"GHSA-q2"}) {
		t.Fatalf("got %+v, want GHSA-q1 and GHSA-q2 once each", got)
	}
}

func sarifMessages(t *testing.T, deps []*entity.Dependency, vulns []*entity.Vulnerability) map[string]string {
	t.Helper()
	f, s := Build(&engine.Result{Dependencies: deps, Vulnerabilities: vulns}, nil, "", fixedNow)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, testTool, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string                `json:"ruleId"`
				Message struct{ Text string } `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range doc.Runs[0].Results {
		got[r.RuleID] = r.Message.Text
	}
	return got
}

func TestSARIFMessageNamesTheUpgradeThatFixesMore(t *testing.T) {
	lodash := rdep("lodash", "4.17.15", "npm", "package-lock.json")
	got := sarifMessages(t, []*entity.Dependency{lodash}, []*entity.Vulnerability{
		rvuln(lodash, "GHSA-a", entity.SeverityHigh, "4.17.19"),
		rvuln(lodash, "GHSA-b", entity.SeverityHigh, "4.17.21"),
		rvuln(lodash, "GHSA-c", entity.SeverityHigh, ""),
	})
	want := map[string]string{
		"GHSA-a": "lodash@4.17.15 is affected by GHSA-a (fixed in 4.17.19). Upgrading to 4.17.21 fixes this and 1 other advisory for this package.",
		"GHSA-b": "lodash@4.17.15 is affected by GHSA-b (fixed in 4.17.21). Upgrading to 4.17.21 fixes this and 1 other advisory for this package.",
		"GHSA-c": "lodash@4.17.15 is affected by GHSA-c (no fix available)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("messages:\n got %v\nwant %v", got, want)
	}
}

// A fixed finding in a package that is recommended for removal must not
// tell the reader that upgrading fixes it.
func TestSARIFMessageDoesNotSuggestUpgradingAMaliciousPackage(t *testing.T) {
	evil := rdep("evil-pkg", "1.0.0", "npm", "package-lock.json")
	got := sarifMessages(t, []*entity.Dependency{evil}, []*entity.Vulnerability{
		rvuln(evil, "MAL-2025-1234", entity.SeverityCritical, ""),
		rvuln(evil, "GHSA-a", entity.SeverityHigh, "1.0.1"),
		rvuln(evil, "GHSA-b", entity.SeverityHigh, "1.0.2"),
	})
	for _, id := range []string{"GHSA-a", "GHSA-b"} {
		m := got[id]
		if strings.Contains(m, "Upgrading to") {
			t.Errorf("%s: message suggests upgrading: %q", id, m)
		}
		if !strings.Contains(m, "remove or replace it") {
			t.Errorf("%s: message does not say to remove or replace: %q", id, m)
		}
	}
}
