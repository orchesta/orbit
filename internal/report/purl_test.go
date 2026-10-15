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
		// hostile names are encoded, never interpreted.
		{entity.EcosystemNpm, "a?b#c@d%e", "1.0.0", "pkg:npm/a%3Fb%23c%40d%25e@1.0.0"},
		{entity.EcosystemNpm, "a\nb\x00", "1.0.0", "pkg:npm/a%0Ab%00@1.0.0"},
		{entity.EcosystemGo, "example.com/a?b/c#d", "1.0.0", "pkg:golang/example.com/a%3Fb/c%23d@v1.0.0"},
		{entity.EcosystemNpm, "a/b", "1.0.0", "pkg:npm/a%2Fb@1.0.0"},
		{entity.EcosystemNpm, "caf\u00e9", "1.0.0", "pkg:npm/caf%C3%A9@1.0.0"},
		{entity.EcosystemPyPI, "Keras", "1.0", "pkg:pypi/keras@1.0"}, // ASCII only
		{entity.EcosystemPyPI, "\u212aeras", "1.0", "pkg:pypi/%E2%84%AAeras@1.0"},
		{entity.EcosystemNpm, "@angular/animation", "", "pkg:npm/%40angular/animation"},
		{entity.EcosystemNpm, "@foo", "1.0.0", "pkg:npm/%40foo@1.0.0"},
		{entity.EcosystemNpm, "@/x", "1.0.0", "pkg:npm/%40%2Fx@1.0.0"},
		// empty, "." and ".." segments have no purl.
		{entity.EcosystemGo, "/", "1.0.0", ""},
		{entity.EcosystemGo, "///", "1.0.0", ""},
		{entity.EcosystemGo, "/a/b", "1.0.0", ""},
		{entity.EcosystemGo, "a/b/", "1.0.0", ""},
		{entity.EcosystemGo, "a//b", "1.0.0", ""},
		{entity.EcosystemGo, "a/../b", "1.0.0", ""},
		{entity.EcosystemGo, "a/./b", "1.0.0", ""},
		{entity.EcosystemNpm, "@a/..", "1.0.0", ""},
		{entity.EcosystemNpm, "..", "1.0.0", ""},
		{entity.EcosystemNuGet, ".", "1.0.0", ""},
		{entity.EcosystemNpm, "", "1.0.0", ""},
		// Go versions.
		{entity.EcosystemGo, "github.com/x/y", "v1.2.3", "pkg:golang/github.com/x/y@v1.2.3"},
		{entity.EcosystemGo, "github.com/x/y", "vlatest", "pkg:golang/github.com/x/y"},
		{entity.EcosystemGo, "github.com/x/y", "latest", "pkg:golang/github.com/x/y"},
		{entity.EcosystemGo, "github.com/x/y/v2", "2.0.0", "pkg:golang/github.com/x/y/v2@v2.0.0"},
		{entity.EcosystemGo, "gopkg.in/yaml.v3", "3.0.1", "pkg:golang/gopkg.in/yaml.v3@v3.0.1"},
		// "+" outside Go, and everything that is not a concrete version.
		{entity.EcosystemNpm, "x", "1.0.0+build.5", "pkg:npm/x@1.0.0%2Bbuild.5"},
		{entity.EcosystemNpm, "x", "latest", "pkg:npm/x"},
		{entity.EcosystemNpm, "x", "1.x", "pkg:npm/x"},
		{entity.EcosystemNpm, "x", "^1.0", "pkg:npm/x"},
		{entity.EcosystemNpm, "x", "~1.0", "pkg:npm/x"},
		{entity.EcosystemNpm, "x", "1.0 ", "pkg:npm/x"},
		{entity.EcosystemNpm, "x", "1.0\n", "pkg:npm/x"},
		{entity.EcosystemNpm, "x", "v1.0.0", "pkg:npm/x"},
		{entity.EcosystemPyPI, "x", "1!2.0", "pkg:pypi/x"},
		// NuGet keeps the case it is given.
		{entity.EcosystemNuGet, "newtonsoft.json", "13.0.1", "pkg:nuget/newtonsoft.json@13.0.1"},
		{entity.EcosystemNuGet, "NEWTONSOFT.JSON", "13.0.1", "pkg:nuget/NEWTONSOFT.JSON@13.0.1"},
	}
	for _, tt := range tests {
		t.Run(string(tt.eco)+"/"+tt.name+"@"+tt.version, func(t *testing.T) {
			if got := PackageURL(tt.eco, tt.name, tt.version); got != tt.want {
				t.Errorf("PackageURL(%s, %q, %q) = %q, want %q", tt.eco, tt.name, tt.version, got, tt.want)
			}
		})
	}
}

func TestBuildPURLAnyVersion(t *testing.T) {
	tests := []struct {
		eco           entity.Ecosystem
		name, version string
		want          string
	}{
		{entity.EcosystemNpm, "left-pad", "^1.0.0", "pkg:npm/left-pad@%5E1.0.0"},
		{entity.EcosystemNpm, "left-pad", ">=1.0.0 <2", "pkg:npm/left-pad@%3E%3D1.0.0%20%3C2"},
		{entity.EcosystemNuGet, "Serilog", "2.*", "pkg:nuget/Serilog@2.%2A"},
		{entity.EcosystemGo, "github.com/x/y", "1.0.0", "pkg:golang/github.com/x/y@v1.0.0"},
		{entity.EcosystemGo, "github.com/x/y", "v1.0.0", "pkg:golang/github.com/x/y@v1.0.0"},
		{entity.EcosystemNpm, "x", "", "pkg:npm/x"},
		{entity.EcosystemNpm, "a//", "1.0.0", "pkg:npm/a%2F%2F@1.0.0"},
		{entity.EcosystemGo, "a//b", "1.0.0", ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.eco)+"/"+tt.name+"@"+tt.version, func(t *testing.T) {
			if got := buildPURL(tt.eco, tt.name, tt.version, true); got != tt.want {
				t.Errorf("buildPURL(%s, %q, %q, true) = %q, want %q", tt.eco, tt.name, tt.version, got, tt.want)
			}
		})
	}
}
