package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCloneArgsSeparatesURLFromOptions(t *testing.T) {
	got := cloneArgs(CloneOptions{URL: "https://github.com/o/r", Branch: "main", DestPath: "/tmp/x", Depth: 1})
	want := []string{"clone", "--depth", "1", "--branch", "main", "--single-branch", "--", "https://github.com/o/r", "/tmp/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cloneArgs = %q, want %q", got, want)
	}
}

func TestCloneRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name string
		opts CloneOptions
		want string
	}{
		{"option injection", CloneOptions{URL: "--upload-pack=touch /tmp/pwned"}, "only plain https"},
		{"file scheme", CloneOptions{URL: "file:///etc"}, "only plain https"},
		{"ext transport", CloneOptions{URL: "ext::sh -c id"}, "only plain https"},
		{"plain http", CloneOptions{URL: "http://github.com/o/r"}, "only plain https"},
		{"embedded credentials", CloneOptions{URL: "https://u:p@github.com/o/r"}, "only plain https"},
		{"branch as option", CloneOptions{URL: "https://github.com/o/r", Branch: "--upload-pack=x"}, "invalid branch"},
		{"token to foreign host", CloneOptions{URL: "https://evil.example/o/r", AuthToken: "tok"}, "untrusted host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.DestPath = filepath.Join(t.TempDir(), "clone")
			err := NewLocalGit().Clone(context.Background(), tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			if _, statErr := os.Stat(tt.opts.DestPath); !os.IsNotExist(statErr) {
				t.Fatal("git must not run for rejected input")
			}
		})
	}
}

func TestGitEnvTokenOnlyForKnownHosts(t *testing.T) {
	for host, user := range map[string]string{"github.com": "x-access-token", "GitLab.com": "oauth2"} {
		env, err := gitEnv(mustURL(t, "https://"+host+"/o/r"), "tok", nil)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":tok"))
		wantKey := "http.https://" + strings.ToLower(host) + "/.extraHeader"
		found := false
		for i := 0; i < 8; i++ {
			if slices.Contains(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, wantKey)) {
				found = slices.Contains(env, fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, header))
				break
			}
		}
		if !found {
			t.Fatalf("%s: scoped auth header %q missing from %q", host, wantKey, env)
		}
		if slices.Contains(env, "GIT_CONFIG_KEY_1=http.extraHeader") || slices.Contains(env, "GIT_CONFIG_KEY_2=http.extraHeader") {
			t.Fatalf("%s: header must be URL-scoped", host)
		}
	}

	if _, err := gitEnv(mustURL(t, "https://evil.example/o/r"), "tok", nil); err == nil {
		t.Fatal("token must not be sent to an unknown host")
	}

	env, err := gitEnv(mustURL(t, "https://evil.example/o/r"), "", nil)
	if err != nil {
		t.Fatalf("anonymous clone of any https host is allowed: %v", err)
	}
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=https", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_KEY_0=core.symlinks", "GIT_CONFIG_VALUE_0=false", "GIT_CONFIG_KEY_1=credential.helper", "GIT_CONFIG_VALUE_1=", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_COUNT=2"} {
		if !slices.Contains(env, want) {
			t.Fatalf("env %q missing %q", env, want)
		}
	}
}

func TestCloneErrorDoesNotLeakCredentials(t *testing.T) {
	for _, raw := range []string{"https://user:s3cret@github.com/o/r", "https://user:s3cret@github.com/o/r\x7f"} {
		err := NewLocalGit().Clone(context.Background(), CloneOptions{URL: raw, DestPath: filepath.Join(t.TempDir(), "clone")})
		if err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("url %q: err = %v, must fail without echoing the secret", raw, err)
		}
		if !strings.Contains(err.Error(), "only plain https") {
			t.Fatalf("err = %v, want 'only plain https'", err)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestGitEnvCredentialScopedToHostAndPort(t *testing.T) {
	cred := &Credential{HostPort: "tfs.local:8443", Username: "orbit", Token: "tok"}
	header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("orbit:tok"))

	env, err := gitEnv(mustURL(t, "https://TFS.local:8443/Col/P/_git/R"), "ignored", cred)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(env, "GIT_CONFIG_KEY_2=http.https://tfs.local:8443/.extraHeader") || !slices.Contains(env, "GIT_CONFIG_VALUE_2="+header) {
		t.Fatalf("scoped header with port missing: %q", env)
	}
	if !slices.Contains(env, "GIT_CONFIG_KEY_3=http.followRedirects") || !slices.Contains(env, "GIT_CONFIG_VALUE_3=false") {
		t.Fatalf("credential clones must not follow redirects: %q", env)
	}
	if strings.Contains(strings.Join(env, "\n"), base64.StdEncoding.EncodeToString([]byte("x-access-token:ignored"))) {
		t.Fatal("AuthToken must not be used when a credential is set")
	}

	for _, raw := range []string{"https://tfs.local:9443/c", "https://tfs.local/c", "https://evil.example:8443/c", "https://github.com/o/r"} {
		if _, err := gitEnv(mustURL(t, raw), "", cred); err == nil || !strings.Contains(err.Error(), "untrusted host") {
			t.Fatalf("%s: err = %v, want untrusted host", raw, err)
		}
	}
	if _, err := gitEnv(mustURL(t, "https://tfs.local/c"), "", &Credential{Username: "orbit", Token: "tok"}); err == nil {
		t.Fatal("credential without a host must be refused")
	}
}

func TestGitEnvCredentialHostIsASCIIOnly(t *testing.T) {
	// U+212A KELVIN SIGN lower-cases to ASCII "k".
	cred := &Credential{HostPort: "tfs.local", Username: "orbit", Token: "tok"}
	if _, err := gitEnv(mustURL(t, "https://tfs.local/c"), "", cred); err != nil {
		t.Fatal(err)
	}
	if _, err := gitEnv(mustURL(t, "https://\u212afs.local/c"), "", &Credential{HostPort: "kfs.local", Username: "orbit", Token: "tok"}); err == nil {
		t.Fatal("non-ASCII host must be refused")
	}
}

func TestGitEnvEmptyCredentialTokenIsAnonymous(t *testing.T) {
	env, err := gitEnv(mustURL(t, "https://github.com/o/r"), "fallback", &Credential{HostPort: "github.com", Username: "orbit"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(env, "GIT_CONFIG_COUNT=2") || strings.Contains(strings.Join(env, "\n"), "extraHeader") {
		t.Fatalf("want anonymous env, got %q", env)
	}
}

// Inherited GIT_CONFIG_PARAMETERS (git -c) and GIT_CONFIG_COUNT/KEY_n/VALUE_n
// would override the hardening gitEnv adds, e.g. re-enable symlinks or
// redirects, so cloneEnv drops them, along with GIT_SSL_NO_VERIFY (would turn
// TLS verification off) and GIT_ASKPASS/SSH_ASKPASS (would hand prompts to an
// outside program), and keeps everything else.
func TestCloneEnvDropsInheritedGitConfig(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"HOME=/home/orbit",
		"GIT_SSL_CAINFO=/etc/orbit/ca-bundle.pem",
		"GIT_CONFIG_PARAMETERS='http.followredirects'='true'",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=core.symlinks",
		"GIT_CONFIG_VALUE_0=true",
		"GIT_CONFIG_KEY_12=x",
		"GIT_CONFIG_VALUE_12=y",
		"GIT_CONFIG_GLOBAL=/home/orbit/.gitconfig",
		"NOT_GIT_CONFIG_PARAMETERS=kept",
		"GIT_SSL_NO_VERIFY=1",
		"GIT_ASKPASS=/tmp/askpass",
		"SSH_ASKPASS=/tmp/ssh-askpass",
	}
	got := cloneEnv(base)
	want := []string{
		"PATH=/usr/bin",
		"HOME=/home/orbit",
		"GIT_SSL_CAINFO=/etc/orbit/ca-bundle.pem",
		"GIT_CONFIG_GLOBAL=/home/orbit/.gitconfig",
		"NOT_GIT_CONFIG_PARAMETERS=kept",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cloneEnv = %q, want %q", got, want)
	}
	// The base slice (os.Environ()) must not be modified in place.
	if base[3] != "GIT_CONFIG_PARAMETERS='http.followredirects'='true'" {
		t.Fatalf("base modified: %q", base)
	}
}

// With a real git, an inherited "git -c" setting must not win over the
// hardening once the environment went through cloneEnv.
func TestCloneEnvHardeningWinsOverInheritedConfig(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	env, err := gitEnv(mustURL(t, "https://github.com/o/r"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	inherited := append(os.Environ(),
		"GIT_CONFIG_PARAMETERS='core.symlinks'='true'",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.symlinks", "GIT_CONFIG_VALUE_0=true",
	)
	get := func(env []string) string {
		cmd := exec.Command(gitPath, "config", "--get", "core.symlinks")
		cmd.Dir = t.TempDir()
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git config: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := get(append(slices.Clone(inherited), env...)); got != "true" {
		t.Logf("note: this git lets GIT_CONFIG_COUNT win over GIT_CONFIG_PARAMETERS (got %q)", got)
	}
	if got := get(append(cloneEnv(inherited), env...)); got != "false" {
		t.Fatalf("core.symlinks = %q, want the hardened false", got)
	}
}
