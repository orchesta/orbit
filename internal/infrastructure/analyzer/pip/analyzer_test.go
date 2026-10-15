package pip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aligoren/orbit/internal/infrastructure/analyzer"
)

func TestGetLatestVersionEscapesName(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"info":{"version":"2.0.0"}}`))
	}))
	defer srv.Close()

	a := NewAnalyzer()
	a.registryURL = srv.URL
	if _, err := a.GetLatestVersion(context.Background(), "evil/../../x?y"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/pypi/evil%2F..%2F..%2Fx%3Fy/json" {
		t.Fatalf("path = %q", gotPath)
	}
}

func manifestDep(name, version string, resolved, dev bool) analyzer.ParsedDependency {
	return analyzer.ParsedDependency{Name: name, CurrentVersion: version, IsDirect: true, Resolved: resolved, Dev: dev}
}

func TestParseRequirementsTxt(t *testing.T) {
	tests := []struct {
		path string
		want []analyzer.ParsedDependency
	}{
		{"requirements.txt", []analyzer.ParsedDependency{
			manifestDep("attrs", "22.1.0", false, false),
			manifestDep("click", "", false, false),
			manifestDep("django", "4.2.1", true, false),
			manifestDep("flask-cors", "4.0.0", true, false),
			manifestDep("legacy", "1.5", false, false),
			manifestDep("multi", "1.0", false, false),
			manifestDep("numpy", "1.24", false, false),
			manifestDep("pandas", "2.0.1", false, false),
			manifestDep("requests", "2.31.0", true, false),
			manifestDep("scipy", "1.11.0", false, false),
			manifestDep("six", "2", false, false),
			manifestDep("tabbed", "2.0", true, false),
			manifestDep("typing-extensions", "4.8.0", true, false),
			manifestDep("wildcard", "1.*", false, false),
		}},
		// The same content in a requirements-dev.txt is dev-only.
		{"svc/requirements-dev.txt", nil},
	}
	a := NewAnalyzer()
	content := readFixture(t, "requirements.txt")
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := a.ParseDependencies(content, tt.path)
			if err != nil {
				t.Fatal(err)
			}
			want := tt.want
			if want == nil {
				for _, d := range tests[0].want {
					d.Dev = true
					want = append(want, d)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got  %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestParseRequirementLineOperators(t *testing.T) {
	tests := []struct {
		line, name, version string
		exact               bool
	}{
		{"a==1.0", "a", "1.0", true},
		{"a===1.0", "a", "1.0", false},
		{"a~=1.0", "a", "1.0", false},
		{"a<=1.0", "a", "1.0", false},
		{"a>=1.0", "a", "1.0", false},
		{"a!=1.0", "a", "1.0", false},
		{"a<1.0", "a", "1.0", false},
		{"a>1.0", "a", "1.0", false},
		{"a>=1.0,<2.0", "a", "1.0", false},
		{"a<2.0,>=1.0", "a", "2.0", false},
		{"a == 1.0", "a", "1.0", true},
		{"a==1.0,!=1.0.1", "a", "1.0", false},
		{"a==1.*", "a", "1.*", false},
		{"a[x,y]==1.0", "a", "1.0", true},
		{"a==1.0 ; python_version < '3.12'", "a", "1.0", true},
		{"a", "a", "", false},
		{"a[x]", "a", "", false},
		{"a ; python_version >= '3.8'", "a", "", false},
		{"a @ https://h/a-1.0.tar.gz", "", "", false}, // direct reference: skipped
		{"legacy (>=1.5)", "legacy", "1.5", false},
		{"legacy (==1.5)", "legacy", "1.5", true},
	}
	for _, tt := range tests {
		name, version, exact := parseRequirementSpec(tt.line)
		if name != tt.name || version != tt.version || exact != tt.exact {
			t.Errorf("parseRequirementSpec(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.line, name, version, exact, tt.name, tt.version, tt.exact)
		}
	}
}

func TestParsePyproject(t *testing.T) {
	tests := []struct {
		fixture string
		want    []analyzer.ParsedDependency
	}{
		{"pyproject/pep621.toml", []analyzer.ParsedDependency{
			manifestDep("click", "", false, false),
			manifestDep("django", "4.2.1", false, false),
			manifestDep("pytest", "7.4.0", false, false),
			manifestDep("requests", "2.28.0", false, false),
			manifestDep("sphinx", "7.0", false, false),
			manifestDep("typing-extensions", "4.8", false, false),
		}},
		{"pyproject/poetry.toml", []analyzer.ParsedDependency{
			manifestDep("anything", "", false, false),
			manifestDep("black", "23.0.0", false, true), // legacy dev-dependencies
			manifestDep("django", "4.2", false, false),
			manifestDep("numpy", "1.26", false, false),
			manifestDep("orjson", "3.9.0", false, false), // ordinary group
			manifestDep("pytest", "7.4.0", false, true),
			manifestDep("requests", "2.28.0", false, false),
			manifestDep("rich", "13.0.0", false, true), // optional group
			manifestDep("sphinx", "7.0.0", false, true),
		}},
		{"pyproject/pep735.toml", []analyzer.ParsedDependency{
			manifestDep("attrs", "23.1", false, false),
			manifestDep("pytest", "7.4", false, true),
			manifestDep("sphinx", "7.0", false, true),
		}},
	}
	a := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			got, err := a.ParseDependencies(readFixture(t, tt.fixture), "pyproject.toml")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParsePipfileNormalizesNames(t *testing.T) {
	got, err := NewAnalyzer().ParseDependencies([]byte("[packages]\nFlask_Cors = \"==4.0.0\"\n"), "Pipfile")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{manifestDep("flask-cors", "4.0.0", false, false)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestDevRequirementsFile(t *testing.T) {
	for name, want := range map[string]bool{
		"requirements.txt":        false,
		"requirements-dev.txt":    true,
		"requirements_test.txt":   true,
		"requirements-tests.txt":  true,
		"dev-requirements.txt":    true,
		"requirements.dev.txt":    true,
		"requirements-lint.txt":   true,
		"requirements-docs.txt":   true,
		"requirements-prod.txt":   false,
		"requirements-docker.txt": false,
		"devops-requirements.txt": false,
		"latest-requirements.txt": false,
		"Requirements-DEV.txt":    true,
	} {
		if got := isDevRequirementsFile(name); got != want {
			t.Errorf("isDevRequirementsFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParsePipfileSkipsNonRegistryEntries(t *testing.T) {
	content := "[packages]\nrequests = \"==2.31.0\"\ngitdep = {git = \"https://x/y.git\", ref = \"main\"}\nlocal = {path = \".\", editable = true}\nurl = \"https://h/x.whl\"\nextras = {version = \"==1.0\", extras = [\"a\"]}\nquoted = {version = \"==2.0\", markers = \"sys_platform == 'x' and path = 1\"}\n"
	got, err := NewAnalyzer().ParseDependencies([]byte(content), "Pipfile")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{
		manifestDep("extras", "1.0", false, false),
		manifestDep("quoted", "2.0", false, false),
		manifestDep("requests", "2.31.0", false, false),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
