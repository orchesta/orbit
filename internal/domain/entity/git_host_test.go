package entity

import (
	"errors"
	"strings"
	"testing"
)

func TestNewGitHost(t *testing.T) {
	valid := []string{
		"https://dev.azure.com/contoso",
		"https://DEV.azure.com/contoso/",
		"https://contoso.visualstudio.com",
		"https://contoso.visualstudio.com/DefaultCollection",
		"https://tfs.local/tfs/DefaultCollection",
		"https://tfs.local:8443/Col",
		"https://tfs.local",
		"https://tfs.local/My%20Col",
	}
	for _, u := range valid {
		h, err := NewGitHost(GitProviderAzureDevOps, "x", u)
		if err != nil {
			t.Errorf("NewGitHost(%q) error: %v", u, err)
			continue
		}
		if h.BaseURL[len(h.BaseURL)-1] == '/' {
			t.Errorf("BaseURL %q keeps trailing slash", h.BaseURL)
		}
	}
	invalid := []string{
		"http://tfs.local/Col",
		"https://u:p@tfs.local/Col",
		"https://tfs.local/Col?a=b",
		"https://tfs.local/Col#f",
		"https://dev.azure.com",
		"https://dev.azure.com/a/b",
		"https://contoso.visualstudio.com/a/b",
		"https://tfs.local/../Col",
		"https://tfs.local/a/./b",
		"https://tfs.local/%2e%2e/Col",
		"https://tfs.local/%2e/Col",
		"https://tfs.local//Col",
		"https://tfs.local/a%2Fb",
		"https://tfs.local/a%2fb",
		"https://tfs.local/a%5Cb",
		"https://tfs.local/a%252eb",
		"https://tfs.local/a%2Eb",
		"https://tfs.local/a b",
		"https://tfs.local/Col\u00e9",
		"https://tfs.local/%C0%AE%C0%AE",
		"https://dev.azure.com./a/b/c",
		"https://dev.azure.com./a/b",
		"https://dev\u212A.local/Col",
		"https:///Col",
		"",
	}
	for _, u := range invalid {
		if _, err := NewGitHost(GitProviderAzureDevOps, "x", u); !errors.Is(err, ErrInvalidGitHost) {
			t.Errorf("NewGitHost(%q) err = %v, want ErrInvalidGitHost", u, err)
		}
	}
	if _, err := NewGitHost(GitProviderGitHub, "x", "https://tfs.local"); !errors.Is(err, ErrInvalidGitHost) {
		t.Errorf("github kind accepted: %v", err)
	}
	if _, err := NewGitHost(GitProviderAzureDevOps, strings.Repeat("a", 100), "https://tfs.local"); err != nil {
		t.Errorf("100-char name rejected: %v", err)
	}
	for _, n := range []string{"", "   ", strings.Repeat("a", 101)} {
		if _, err := NewGitHost(GitProviderAzureDevOps, n, "https://tfs.local"); !errors.Is(err, ErrInvalidGitHost) {
			t.Errorf("name %q accepted: %v", n, err)
		}
	}
}

func TestHostPort(t *testing.T) {
	h, err := NewGitHost(GitProviderAzureDevOps, "x", "https://TFS.local:8443/Col")
	if err != nil {
		t.Fatal(err)
	}
	if h.BaseURL != "https://tfs.local:8443/Col" {
		t.Errorf("BaseURL = %q", h.BaseURL)
	}
	if h2, err := NewGitHost(GitProviderAzureDevOps, "x", "HTTPS://TFS.Local/Col/"); err != nil || h2.BaseURL != "https://tfs.local/Col" {
		t.Errorf("lowercase BaseURL: %v %v", h2, err)
	}
	if got := h.HostPort(); got != "tfs.local:8443" {
		t.Errorf("HostPort = %q", got)
	}
}

func TestValidateHostedRepositoryURL(t *testing.T) {
	mk := func(u string) *GitHost {
		h, err := NewGitHost(GitProviderAzureDevOps, "x", u)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	cloud := mk("https://dev.azure.com/contoso")
	vs := mk("https://contoso.visualstudio.com")
	srv := mk("https://tfs.local:8443/tfs/Col")
	space := mk("https://tfs.local/My%20Col")

	tests := []struct {
		name string
		h    *GitHost
		url  string
		ok   bool
	}{
		{"project repo", cloud, "https://dev.azure.com/contoso/P/_git/R", true},
		{"no project", cloud, "https://dev.azure.com/contoso/_git/R", true},
		{"encoded spaces", cloud, "https://dev.azure.com/contoso/P%20X/_git/R%20Y", true},
		{"git suffix", cloud, "https://dev.azure.com/contoso/P/_git/R.git", true},
		{"case-insensitive", cloud, "https://DEV.azure.com/Contoso/P/_git/R", true},
		{"vs no collection", vs, "https://contoso.visualstudio.com/P/_git/R", true},
		{"server", srv, "https://tfs.local:8443/tfs/Col/P/_git/R", true},
		{"vs default collection", vs, "https://contoso.visualstudio.com/DefaultCollection/P/_git/R", true},
		{"vs default collection case", vs, "https://contoso.visualstudio.com/defaultcollection/_git/R", true},
		{"space in base path", space, "https://tfs.local/My%20Col/P/_git/R", true},
		{"raw space in base path", space, "https://tfs.local/My Col/P/_git/R", false},
		{"default collection on server", srv, "https://tfs.local:8443/tfs/Col/DefaultCollection/P/_git/R", false},
		{"default collection on cloud", cloud, "https://dev.azure.com/contoso/DefaultCollection/P/_git/R", false},
		{"encoded dot in segment", cloud, "https://dev.azure.com/contoso/P/_git/R%2Ex", false},
		{"encoded dot in project", cloud, "https://dev.azure.com/contoso/P%2eX/_git/R", false},
		{"encoded slash raw space", cloud, "https://dev.azure.com/contoso/P%2F_git/R Y", false},
		{"encoded slash non-ascii", cloud, "https://dev.azure.com/contoso/P%2F_git/R\u00e9", false},
		{"raw space", cloud, "https://dev.azure.com/contoso/P X/_git/R", false},
		{"non-ascii", cloud, "https://dev.azure.com/contoso/P/_git/R\u00e9", false},
		{"overlong utf8", cloud, "https://dev.azure.com/contoso/P/_git/%C0%AE%C0%AE", false},
		{"overlong slash", cloud, "https://dev.azure.com/contoso/P%C0%AFX/_git/R", false},
		{"empty project segment", cloud, "https://dev.azure.com/contoso//_git/R", false},
		{"other host", cloud, "https://evil.com/contoso/P/_git/R", false},
		{"other port", srv, "https://tfs.local/tfs/Col/P/_git/R", false},
		{"port on cloud", cloud, "https://dev.azure.com:444/contoso/P/_git/R", false},
		{"outside base path", cloud, "https://dev.azure.com/other/P/_git/R", false},
		{"prefix only", cloud, "https://dev.azure.com/contosoX/P/_git/R", false},
		{"http", cloud, "http://dev.azure.com/contoso/P/_git/R", false},
		{"no _git", cloud, "https://dev.azure.com/contoso/P/R", false},
		{"no repo", cloud, "https://dev.azure.com/contoso/P/_git", false},
		{"extra", cloud, "https://dev.azure.com/contoso/P/_git/R/extra", false},
		{"encoded slash", cloud, "https://dev.azure.com/contoso/P%2FX/_git/R", false},
		{"encoded backslash", cloud, "https://dev.azure.com/contoso/P%5CX/_git/R", false},
		{"double encoded", cloud, "https://dev.azure.com/contoso/P/_git/%252e%252e", false},
		{"encoded dotdot", cloud, "https://dev.azure.com/contoso/P/_git/%2e%2e", false},
		{"dotdot", cloud, "https://dev.azure.com/contoso/../contoso/P/_git/R", false},
		{"control char", cloud, "https://dev.azure.com/contoso/P%0A/_git/R", false},
		{"empty segment", cloud, "https://dev.azure.com/contoso/P//_git/R", false},
		{"userinfo", cloud, "https://contoso@dev.azure.com/contoso/P/_git/R", false},
		{"query", cloud, "https://dev.azure.com/contoso/P/_git/R?a=b", false},
		{"fragment", cloud, "https://dev.azure.com/contoso/P/_git/R#f", false},
		{"nil host", nil, "https://dev.azure.com/contoso/P/_git/R", false},
	}
	for _, tc := range tests {
		err := ValidateHostedRepositoryURL(tc.h, tc.url)
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrInvalidRepositoryURL) {
			t.Errorf("%s: err = %v, want ErrInvalidRepositoryURL", tc.name, err)
		}
	}
}

func TestKnownProviderAndAzureWithoutHost(t *testing.T) {
	for _, p := range []GitProvider{GitProviderGitHub, GitProviderGitLab, GitProviderAzureDevOps} {
		if !KnownProvider(p) {
			t.Errorf("%s not known", p)
		}
	}
	if KnownProvider("bitbucket") {
		t.Error("bitbucket known")
	}
	err := ValidateRepositoryURL(GitProviderAzureDevOps, "https://dev.azure.com/o/P/_git/R")
	if !errors.Is(err, ErrInvalidRepositoryURL) || !strings.Contains(err.Error(), "need a connection") {
		t.Errorf("err = %v", err)
	}
}

func TestValidateHostedRepositoryURLHostHygiene(t *testing.T) {
	h, err := NewGitHost(GitProviderAzureDevOps, "x", "https://tfs.local/Col")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"https://tfs.local./Col/P/_git/R",
		"https://tfs.l\u00f6cal/Col/P/_git/R",
	} {
		if err := ValidateHostedRepositoryURL(h, u); !errors.Is(err, ErrInvalidRepositoryURL) {
			t.Errorf("%q err = %v", u, err)
		}
	}
	k, err := NewGitHost(GitProviderAzureDevOps, "x", "https://tfs.local")
	if err != nil {
		t.Fatal(err)
	}
	// KELVIN SIGN lowercases to ASCII "k" under Unicode folding.
	kh := &GitHost{Kind: GitProviderAzureDevOps, BaseURL: "https://tfs.local"}
	_ = k
	if err := ValidateHostedRepositoryURL(kh, "https://\u212Aeys.local/P/_git/R"); err == nil {
		t.Error("kelvin host accepted")
	}
	kh2 := &GitHost{Kind: GitProviderAzureDevOps, BaseURL: "https://keys.local"}
	if err := ValidateHostedRepositoryURL(kh2, "https://\u212Aeys.local/P/_git/R"); !errors.Is(err, ErrInvalidRepositoryURL) {
		t.Errorf("kelvin host err = %v", err)
	}
}

// Percent-encoding an unreserved character (RFC 3986: ALPHA, DIGIT, "-", ".",
// "_", "~") spells the same path a second way, so it is rejected; "%20" is
// still how Azure names carry spaces.
func TestEncodedUnreservedCharactersAreRejected(t *testing.T) {
	for _, u := range []string{
		"https://tfs.local/%41col",
		"https://tfs.local/C%6Fl",
		"https://tfs.local/C%6fl",
		"https://tfs.local/Col%50",
		"https://tfs.local/Col%2D1",
		"https://tfs.local/Col%5F1",
		"https://tfs.local/Col%7E1",
		"https://tfs.local/Col%30",
	} {
		if _, err := NewGitHost(GitProviderAzureDevOps, "x", u); !errors.Is(err, ErrInvalidGitHost) {
			t.Errorf("NewGitHost(%q) err = %v, want ErrInvalidGitHost", u, err)
		}
	}
	h, err := NewGitHost(GitProviderAzureDevOps, "x", "https://dev.azure.com/contoso")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"https://dev.azure.com/contoso/P/%5Fgit/R",
		"https://dev.azure.com/contoso/P/_git/%50",
		"https://dev.azure.com/contoso/%41/_git/R",
		"https://dev.azure.com/%63ontoso/P/_git/R",
		"https://dev.azure.com/contoso/P/_git/R%7e1",
		"https://dev.azure.com/contoso/P/_git/R%2d1",
		"https://dev.azure.com/contoso/P/_git/R%39",
	} {
		if err := ValidateHostedRepositoryURL(h, u); !errors.Is(err, ErrInvalidRepositoryURL) {
			t.Errorf("%q err = %v, want ErrInvalidRepositoryURL", u, err)
		}
	}
	for _, u := range []string{
		"https://dev.azure.com/contoso/P%20X/_git/R%20Y",
		"https://dev.azure.com/contoso/P/_git/R%21",
		"https://dev.azure.com/contoso/P/_git/R%C3%A9",
	} {
		if err := ValidateHostedRepositoryURL(h, u); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
}

// An explicit default port names the same host as no port, so it is dropped
// from the stored base URL and from HostPort (the credential scope).
func TestNewGitHostStripsDefaultPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://dev.azure.com:443/contoso": "https://dev.azure.com/contoso",
		"https://TFS.local:443/tfs/Col/":    "https://tfs.local/tfs/Col",
		"https://tfs.local:443":             "https://tfs.local",
		"https://[::1]:443/Col":             "https://[::1]/Col",
		"https://tfs.local:8443/Col":        "https://tfs.local:8443/Col",
	} {
		h, err := NewGitHost(GitProviderAzureDevOps, "x", in)
		if err != nil {
			t.Errorf("NewGitHost(%q): %v", in, err)
			continue
		}
		if h.BaseURL != want {
			t.Errorf("NewGitHost(%q).BaseURL = %q, want %q", in, h.BaseURL, want)
		}
	}
	h, err := NewGitHost(GitProviderAzureDevOps, "x", "https://tfs.local:443/Col")
	if err != nil {
		t.Fatal(err)
	}
	if got := h.HostPort(); got != "tfs.local" {
		t.Errorf("HostPort = %q, want tfs.local", got)
	}
	// Repository URLs as the server reports them (no port) now match.
	if err := ValidateHostedRepositoryURL(h, "https://tfs.local/Col/P/_git/R"); err != nil {
		t.Errorf("repository on the default port rejected: %v", err)
	}
}

// A server whose public URL carries the default port reports repository URLs
// with ":443"; the canonical form drops it so they match the connection
// (stored without ":443") and dedupe against the plain spelling.
func TestCanonicalHostedRepositoryURL(t *testing.T) {
	cloud, err := NewGitHost(GitProviderAzureDevOps, "x", "https://dev.azure.com/acme")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewGitHost(GitProviderAzureDevOps, "x", "https://tfs.local:443/tfs/Col")
	if err != nil {
		t.Fatal(err)
	}
	alt, err := NewGitHost(GitProviderAzureDevOps, "x", "https://tfs.local:8443/tfs/Col")
	if err != nil {
		t.Fatal(err)
	}
	ok := []struct {
		h        *GitHost
		in, want string
	}{
		{cloud, "https://dev.azure.com:443/acme/P/_git/R", "https://dev.azure.com/acme/P/_git/R"},
		{cloud, "https://dev.azure.com/acme/P/_git/R", "https://dev.azure.com/acme/P/_git/R"},
		{cloud, "https://dev.azure.com:443/acme/P%20X/_git/R%20Y", "https://dev.azure.com/acme/P%20X/_git/R%20Y"},
		{srv, "https://tfs.local:443/tfs/Col/P/_git/R", "https://tfs.local/tfs/Col/P/_git/R"},
		{srv, "https://tfs.local/tfs/Col/_git/R", "https://tfs.local/tfs/Col/_git/R"},
		{alt, "https://tfs.local:8443/tfs/Col/P/_git/R", "https://tfs.local:8443/tfs/Col/P/_git/R"},
	}
	for _, tc := range ok {
		got, err := CanonicalHostedRepositoryURL(tc.h, tc.in)
		if err != nil || got != tc.want {
			t.Errorf("CanonicalHostedRepositoryURL(%s, %q) = %q, %v; want %q", tc.h.BaseURL, tc.in, got, err, tc.want)
		}
	}
	bad := []struct {
		h  *GitHost
		in string
	}{
		{alt, "https://tfs.local:443/tfs/Col/P/_git/R"},    // the connection's port is 8443
		{cloud, "https://dev.azure.com:444/acme/P/_git/R"}, // another port
		{cloud, "https://evil.example:443/acme/P/_git/R"},  // another host
		{cloud, "http://dev.azure.com:443/acme/P/_git/R"},  // not https
		{cloud, "https://dev.azure.com:443/acme/P/%5Fgit/R"},
		{nil, "https://dev.azure.com/acme/P/_git/R"},
	}
	for _, tc := range bad {
		if got, err := CanonicalHostedRepositoryURL(tc.h, tc.in); !errors.Is(err, ErrInvalidRepositoryURL) {
			t.Errorf("CanonicalHostedRepositoryURL(%q) = %q, %v; want ErrInvalidRepositoryURL", tc.in, got, err)
		}
	}
}
