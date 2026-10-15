package report

import (
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
)

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
