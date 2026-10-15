package npm

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

// syntheticPnpmLock returns a pnpm v9 lockfile with n packages (n even):
// pkg-i, a dependency of the root importer, depends on dep-i. Every fourth
// pkg-i is a devDependency, so it and its dep-i are dev only.
func syntheticPnpmLock(n int) []byte {
	var b bytes.Buffer
	b.WriteString("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n")
	for i := 0; i < n/2; i++ {
		if i%4 != 0 {
			fmt.Fprintf(&b, "      pkg-%d:\n        specifier: ^1.0.0\n        version: 1.0.%d\n", i, i)
		}
	}
	b.WriteString("    devDependencies:\n")
	for i := 0; i < n/2; i += 4 {
		fmt.Fprintf(&b, "      pkg-%d:\n        specifier: ^1.0.0\n        version: 1.0.%d\n", i, i)
	}
	b.WriteString("\npackages:\n\n")
	for i := 0; i < n/2; i++ {
		fmt.Fprintf(&b, "  pkg-%d@1.0.%d:\n    resolution: {integrity: sha512-%060d}\n\n", i, i, i)
		fmt.Fprintf(&b, "  dep-%d@2.0.%d:\n    resolution: {integrity: sha512-%060d}\n\n", i, i, i)
	}
	b.WriteString("snapshots:\n\n")
	for i := 0; i < n/2; i++ {
		fmt.Fprintf(&b, "  pkg-%d@1.0.%d:\n    dependencies:\n      dep-%d: 2.0.%d\n\n", i, i, i, i)
		fmt.Fprintf(&b, "  dep-%d@2.0.%d: {}\n\n", i, i)
	}
	return b.Bytes()
}

// syntheticYarnBerry returns a yarn berry lockfile with n packages.
func syntheticYarnBerry(n int) []byte {
	var b bytes.Buffer
	b.WriteString("__metadata:\n  version: 8\n  cacheKey: 10c0\n\n")
	for i := range n {
		fmt.Fprintf(&b, "\"pkg-%d@npm:^1.0.0\":\n  version: 1.0.%d\n  resolution: \"pkg-%d@npm:1.0.%d\"\n  checksum: 10c0/%060d\n  languageName: node\n  linkType: hard\n\n", i, i, i, i, i)
	}
	return b.Bytes()
}

func TestSyntheticYAMLLockfiles(t *testing.T) {
	const n = 400
	deps, err := NewAnalyzer().ParseDependencies(syntheticPnpmLock(n), "pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != n {
		t.Fatalf("pnpm: %d dependencies, want %d", len(deps), n)
	}
	for _, d := range deps {
		var i int
		if _, err := fmt.Sscanf(d.Name[strings.Index(d.Name, "-")+1:], "%d", &i); err != nil {
			t.Fatalf("unexpected package %s", d.Name)
		}
		if want := i%4 == 0; d.Dev != want || !d.Resolved {
			t.Errorf("pnpm: %s@%s dev=%v resolved=%v, want dev=%v", d.Name, d.CurrentVersion, d.Dev, d.Resolved, want)
		}
	}

	deps, err = NewAnalyzer().ParseDependencies(syntheticYarnBerry(n), "yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != n {
		t.Fatalf("yarn berry: %d dependencies, want %d", len(deps), n)
	}
}

// YAML lockfiles are walked as nodes. Decoding them into Go maps or structs
// with yaml.v3 is quadratic in the number of keys (it checks them for
// duplicates pairwise) and rejects a repeated key. These lockfiles repeat a
// key, so they fail to parse if map decoding comes back.
func TestYAMLLockfilesWithDuplicateKeys(t *testing.T) {
	tests := []struct {
		file, content string
		want          []analyzer.ParsedDependency
	}{
		{"pnpm-lock.yaml", `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      ms:
        specifier: ^2.0.0
        version: 2.0.0

packages:

  ms@2.0.0:
    resolution: {integrity: sha512-a}

  ms@2.0.0:
    resolution: {integrity: sha512-a}

snapshots:

  ms@2.0.0: {}
`, []analyzer.ParsedDependency{locked("ms", "2.0.0", false)}},
		{"yarn.lock", `__metadata:
  version: 8
  cacheKey: 10c0

"express@npm:^4.18.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  languageName: node
  linkType: hard

"express@npm:^4.18.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  languageName: node
  linkType: hard
`, []analyzer.ParsedDependency{locked("express", "4.18.2", false)}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := NewAnalyzer().ParseDependencies([]byte(tt.content), tt.file)
			if err != nil {
				t.Fatalf("parse failed (map decoding is back?): %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestYAMLLockfileSizeCap(t *testing.T) {
	for _, file := range []string{"pnpm-lock.yaml", "yarn.lock"} {
		header := "lockfileVersion: '9.0'\n"
		if file == "yarn.lock" {
			header = "__metadata:\n  version: 8\n"
		}
		content := []byte(header + "#" + strings.Repeat("x", maxYAMLLockfileBytes) + "\n")
		_, err := NewAnalyzer().ParseDependencies(content, file)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("%s over the YAML cap: err = %v, want a size error", file, err)
		}
	}
}

// Parse time should grow linearly with size: compare ns/op of the 4k and 32k
// cases (go test -run '^$' -bench 'ParsePnpmLock|ParseYarnBerry').

func BenchmarkParsePnpmLock(b *testing.B) {
	benchmarkParse(b, "pnpm-lock.yaml", syntheticPnpmLock)
}

func BenchmarkParseYarnBerry(b *testing.B) {
	benchmarkParse(b, "yarn.lock", syntheticYarnBerry)
}

func benchmarkParse(b *testing.B, file string, gen func(int) []byte) {
	for _, n := range []int{4000, 32000} {
		content := gen(n)
		b.Run(fmt.Sprintf("%dk", n/1000), func(b *testing.B) {
			b.SetBytes(int64(len(content)))
			for b.Loop() {
				if _, err := NewAnalyzer().ParseDependencies(content, file); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
