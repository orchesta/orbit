package engine_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

func licensesOf(deps []*entity.Dependency) []string {
	var out []string
	for _, d := range deps {
		out = append(out, fmt.Sprintf("%s %s@%s license=%q", d.ManifestFile, d.Name, d.CurrentVersion, d.License))
	}
	return out
}

// licenseTree has a lockfile that records one license, a go.mod, an exact
// pin and a range in requirements.txt, and a NuGet project with a plain
// version and a range.
func licenseTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"package.json":        `{"dependencies":{"a":"^1.0.0","b":"^2.0.0"}}`,
		"package-lock.json":   `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","license":"MIT"},"node_modules/b":{"version":"2.0.0"},"node_modules/c/node_modules/b":{"version":"2.0.0"}}}`,
		"svc/go.mod":          "module example.com/svc\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n",
		"py/requirements.txt": "requests==2.31.0\nflask>=2.0\n",
		"net/App.csproj":      `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /><PackageReference Include="Serilog" Version="[3.0,4.0)" /></ItemGroup></Project>`,
	})
}

func TestAnalyzeKeepsLockfileLicensesWithoutAFetcher(t *testing.T) {
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), licenseTree(t))
	got := licensesOf(res.Dependencies)
	if !slices.Contains(got, `package-lock.json a@1.0.0 license="MIT"`) || !slices.Contains(got, `package-lock.json b@2.0.0 license=""`) {
		t.Fatalf("licenses:\n%s", strings.Join(got, "\n"))
	}
}
