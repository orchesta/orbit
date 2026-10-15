package entity

import (
	"errors"
	"testing"
)

func TestValidateRepositoryURL(t *testing.T) {
	tests := []struct {
		provider GitProvider
		url      string
		ok       bool
	}{
		{GitProviderGitHub, "https://github.com/expressjs/express", true},
		{GitProviderGitHub, "https://github.com/expressjs/express.git", true},
		{GitProviderGitHub, "https://github.com/expressjs/express/", true},
		{GitProviderGitHub, "https://GitHub.com/expressjs/express", true},
		{GitProviderGitLab, "https://gitlab.com/group/sub/project", true},
		{GitProviderGitHub, "https://evil.example/expressjs/express", false},
		{GitProviderGitHub, "https://www.github.com/expressjs/express", false},
		{GitProviderGitHub, "https://gitlab.com/group/project", false},
		{GitProviderGitHub, "http://github.com/expressjs/express", false},
		{GitProviderGitHub, "file:///etc/passwd", false},
		{GitProviderGitHub, "--upload-pack=touch /tmp/pwned", false},
		{GitProviderGitHub, "https://user:pass@github.com/expressjs/express", false},
		{GitProviderGitHub, "https://github.com:8443/expressjs/express", false},
		{GitProviderGitHub, "https://github.com/expressjs", false},
		{GitProviderGitHub, "https://github.com/expressjs/express?x=1", false},
		{GitProviderGitHub, "https://github.com/o/../r", false},
		{GitProviderGitHub, "https://github.com/o/%2e%2e/r", false},
		{GitProviderGitHub, "https://github.com/o/%2E%2E/r", false},
		{GitProviderGitHub, "https://github.com/./r", false},
		{GitProviderGitHub, "https://github.com/o/r/..", false},
		{GitProviderGitHub, "https://github.com/o/%252e%252e/r", false},
		{GitProviderGitHub, "https://github.com/o/r%2Fx", false},
		{GitProvider("bitbucket"), "https://bitbucket.org/a/b", false},
	}
	for _, tt := range tests {
		err := ValidateRepositoryURL(tt.provider, tt.url)
		if tt.ok && err != nil {
			t.Errorf("%s %q: unexpected error %v", tt.provider, tt.url, err)
		}
		if !tt.ok && !errors.Is(err, ErrInvalidRepositoryURL) {
			t.Errorf("%s %q: want ErrInvalidRepositoryURL, got %v", tt.provider, tt.url, err)
		}
	}
}

func TestNormalizeRepositoryURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://GitHub.com/O/Repo.git":  "https://github.com/o/repo",
		"https://github.com/o/repo/":     "https://github.com/o/repo",
		"https://github.com/o/repo":      "https://github.com/o/repo",
		"https://github.com/o/repo.git/": "https://github.com/o/repo",
		"https://github.com/o/repo//":    "https://github.com/o/repo",
	} {
		if got := NormalizeRepositoryURL(in); got != want {
			t.Errorf("NormalizeRepositoryURL(%q) = %q, want %q", in, got, want)
		}
	}
}
