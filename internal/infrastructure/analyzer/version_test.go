package analyzer

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		current, latest, want string
	}{
		{"1.9.0", "1.10.0", "minor"},
		{"2.0.0", "1.9.9", "none"},
		{"1.2.3", "1.2.3", "none"},
		{"1.2.3-beta", "1.2.3", "patch"},
		{"1.2.3", "1.2.3-beta", "none"},
		{"1.0.0-alpha", "1.0.0-beta", "patch"},
		{"1.0.0-beta.2", "1.0.0-beta.11", "patch"},
		{"1.2", "1.3.0", "minor"},
		{"v1.2.3", "1.3.0", "minor"},
		{"^1.2.3", "1.2.4", "patch"},
		{"1.2.3+build1", "1.2.3+build2", "none"},
		{"*", "1.0.0", "none"},
		{"", "1.0.0", "none"},
		{"1.0.0", "", "none"},
		{"latest", "1.0.0", "none"},
		{"4.17.21", "5.0.0", "major"},
		{"1.2.3", "2.0.0", "major"},
		{"1.2.3.4", "1.3.0.0", "minor"},
		{"1.2.3.4", "1.2.3.5", "patch"},
		{"1.2.3.5", "1.2.3.4", "none"},
		{"2.0rc1", "2.0", "patch"},
		{"2.0rc1", "3.0.0", "major"},
		{"2.0b1", "2.0rc1", "patch"},
		{"2.0.dev1", "2.0a1", "patch"},
		{"1.0.post1", "1.0.post2", "patch"},
		{"1.0", "1.0.post1", "patch"},
		{"1.0.post1", "1.0", "none"},
		{"1.2.3.post1", "1.2.3.post1", "none"},
		{"1!2.0", "1!2.1", "minor"},
		{"1!1.0", "2.0", "none"},
		{"0.0.0-20230101000000-abcdef", "1.0.0", "major"},
		{"v2.0.0+incompatible", "v2.1.0+incompatible", "minor"},
	}
	for _, tt := range tests {
		if got := CompareVersions(tt.current, tt.latest); got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %q, want %q", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestCompareVersionOrder(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"4.17.21", "4.17.15", 1, true},             // npm semver
		{"1.0.0-beta.2", "1.0.0-beta.11", -1, true}, // numeric pre-release identifiers
		{"1.0.0-rc.1", "1.0.0", -1, true},
		{"3.0.7", "3.0.7", 0, true},
		{"3.0.10", "3.0.7", 1, true},   // not string order
		{"2.0rc1", "2.0", -1, true},    // PEP 440 pre-release
		{"1.0.post1", "1.0", 1, true},  // PEP 440 post-release
		{"1!1.0", "2.0", 1, true},      // PEP 440 epoch
		{"6.0.0.1", "6.0.0", 1, true},  // NuGet four segments
		{"v0.17.0", "0.17.0", 0, true}, // Go with and without v
		{"v0.0.0-20230101000000-abcdef", "v0.1.0", -1, true},
		{"v2.0.0+incompatible", "v2.0.1+incompatible", -1, true},
		{"", "1.0.0", 0, false},
		{"1.0.0", "latest", 0, false},
		{">=1.0.0 <2", "1.0.0", 0, false},
	}
	for _, tt := range tests {
		got, ok := CompareVersionOrder(tt.a, tt.b)
		if got != tt.want || ok != tt.ok {
			t.Errorf("CompareVersionOrder(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
}
