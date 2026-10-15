package report

import (
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

func TestPackageURL(t *testing.T) {
	tests := []struct {
		eco           entity.Ecosystem
		name, version string
		want          string
	}{
		// npm: the scope's "@" is always encoded; names keep their case.
		{entity.EcosystemNpm, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{entity.EcosystemNpm, "@angular/animation", "12.3.1", "pkg:npm/%40angular/animation@12.3.1"},
		{entity.EcosystemNpm, "JSONStream", "1.3.5", "pkg:npm/JSONStream@1.3.5"},
		{entity.EcosystemNpm, "lodash", "", "pkg:npm/lodash"},
		// pypi: lower case, "_" becomes "-", "." stays.
		{entity.EcosystemPyPI, "Django_Package", "1.11.1.dev1", "pkg:pypi/django-package@1.11.1.dev1"},
		{entity.EcosystemPyPI, "zope.interface", "5.4.0", "pkg:pypi/zope.interface@5.4.0"},
		// nuget: no namespace, case kept.
		{entity.EcosystemNuGet, "EnterpriseLibrary.Common", "6.0.1304", "pkg:nuget/EnterpriseLibrary.Common@6.0.1304"},
		// golang: module path split at the last "/", "v" restored, "+" encoded.
		{entity.EcosystemGo, "github.com/gorilla/context", "1.1.2", "pkg:golang/github.com/gorilla/context@v1.1.2"},
		{entity.EcosystemGo, "github.com/BurntSushi/toml", "1.6.0", "pkg:golang/github.com/BurntSushi/toml@v1.6.0"},
		{entity.EcosystemGo, "github.com/docker/docker", "20.10.7+incompatible", "pkg:golang/github.com/docker/docker@v20.10.7%2Bincompatible"},
		{entity.EcosystemGo, "golang.org/x/mod", "0.0.0-20240101000000-abcdef123456", "pkg:golang/golang.org/x/mod@v0.0.0-20240101000000-abcdef123456"},
		// a range, a wildcard or a URL is not a version: it is left out.
		{entity.EcosystemNuGet, "Newtonsoft.Json", "[13.0,14.0)", "pkg:nuget/Newtonsoft.Json"},
		{entity.EcosystemNuGet, "Serilog", "2.*", "pkg:nuget/Serilog"},
		{entity.EcosystemNpm, "x", "git+https://example.com/x.git", "pkg:npm/x"},
		// characters outside the purl alphabet are percent-encoded.
		{entity.EcosystemNpm, "a b", "1.0.0", "pkg:npm/a%20b@1.0.0"},
		{entity.Ecosystem("cargo"), "serde", "1.0.0", ""},
	}
	for _, tt := range tests {
		if got := PackageURL(tt.eco, tt.name, tt.version); got != tt.want {
			t.Errorf("PackageURL(%s, %q, %q) = %q, want %q", tt.eco, tt.name, tt.version, got, tt.want)
		}
	}
}
