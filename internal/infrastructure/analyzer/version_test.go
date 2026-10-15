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
