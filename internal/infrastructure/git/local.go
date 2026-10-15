package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// LocalGit provides local git operations using the git CLI.
// Both GitHub and GitLab clients delegate to this for cloning.
type LocalGit struct{}

// NewLocalGit creates a new LocalGit.
func NewLocalGit() *LocalGit {
	return &LocalGit{}
}

// Clone clones a repository using the git CLI. Only plain https URLs are
// accepted, and a token is only ever sent to its provider's host.
func (g *LocalGit) Clone(ctx context.Context, opts CloneOptions) error {
	u, err := url.Parse(opts.URL)
	if err != nil {
		// The raw string may carry credentials, so never echo it.
		return fmt.Errorf("refusing to clone: only plain https URLs are allowed (unparseable url)")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("refusing to clone %q: only plain https URLs are allowed", u.Redacted())
	}
	if strings.HasPrefix(opts.Branch, "-") {
		return fmt.Errorf("invalid branch name %q", opts.Branch)
	}
	env, err := gitEnv(u, opts.AuthToken, opts.Credential)
	if err != nil {
		return err
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(opts.DestPath), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	cmd := exec.CommandContext(ctx, "git", cloneArgs(opts)...)
	cmd.Env = append(cloneEnv(os.Environ()), env...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %s: %w", string(output), err)
	}

	return nil
}

// cloneEnv returns base without the variables that would weaken a clone:
// GIT_CONFIG_PARAMETERS (what "git -c" sets) and GIT_CONFIG_COUNT,
// GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n>, which would override the
// hardening gitEnv adds ("-c" settings take precedence over GIT_CONFIG_COUNT
// entries) or shift its numbering; GIT_SSL_NO_VERIFY, which turns TLS
// verification off; and GIT_ASKPASS and SSH_ASKPASS, which hand credential
// prompts to an outside program. Everything else, such as GIT_SSL_CAINFO and
// proxy settings, is kept.
func cloneEnv(base []string) []string {
	out := make([]string, 0, len(base))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "GIT_CONFIG_PARAMETERS", name == "GIT_CONFIG_COUNT",
			strings.HasPrefix(name, "GIT_CONFIG_KEY_"), strings.HasPrefix(name, "GIT_CONFIG_VALUE_"),
			name == "GIT_SSL_NO_VERIFY", name == "GIT_ASKPASS", name == "SSH_ASKPASS":
			continue
		}
		out = append(out, kv)
	}
	return out
}

// cloneArgs builds the git clone argument list. "--" stops option parsing so
// the URL and destination can never be read as flags.
func cloneArgs(opts CloneOptions) []string {
	args := []string{"clone"}
	if opts.Depth > 0 {
		args = append(args, "--depth", strconv.Itoa(opts.Depth))
	}
	if opts.Branch != "" {
		args = append(args, "--branch", opts.Branch, "--single-branch")
	}
	return append(args, "--", opts.URL, opts.DestPath)
}

// tokenUsers maps the only hosts that may receive a stored access token to
// the basic-auth username each expects alongside it.
var tokenUsers = map[string]string{
	"github.com": "x-access-token",
	"gitlab.com": "oauth2",
}

// gitEnv returns environment variables that harden the git invocation:
// https only, no system config, no prompts, and symlinks checked out as plain
// files. A credential, or else a token for a known provider host, is passed as
// an Authorization header scoped to that exact host (and port) through
// GIT_CONFIG_*, so it never appears in argv, the clone URL or .git/config.
func gitEnv(u *url.URL, token string, cred *Credential) ([]string, error) {
	// An empty credential.helper resets the list, disabling any helper.
	cfg := [][2]string{{"core.symlinks", "false"}, {"credential.helper", ""}}
	switch {
	case cred != nil && cred.Token == "":
		// A credential without a token means an anonymous clone; AuthToken is
		// never used as a fallback.
	case cred != nil:
		// ASCII-only comparison: Unicode case folding must not make another
		// host (e.g. one with a KELVIN SIGN) match.
		if cred.HostPort == "" || !isASCII(u.Host) || strings.ToLower(u.Host) != cred.HostPort {
			return nil, fmt.Errorf("refusing to send credentials to untrusted host %q", u.Host)
		}
		enc := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Token))
		cfg = append(cfg, [2]string{"http.https://" + strings.ToLower(cred.HostPort) + "/.extraHeader", "Authorization: Basic " + enc})
		// git evaluates http.<url>.extraHeader against the original URL only
		// and would resend the header to a redirect target. So a credentialed
		// clone never follows redirects: against a server that redirects it
		// fails closed ("returned error: 302") instead of leaking the token.
		cfg = append(cfg, [2]string{"http.followRedirects", "false"})
	case token != "":
		host := u.Hostname()
		user, ok := tokenUsers[strings.ToLower(host)]
		if !ok {
			return nil, fmt.Errorf("refusing to send credentials to untrusted host %q", host)
		}
		enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
		cfg = append(cfg, [2]string{"http.https://" + strings.ToLower(host) + "/.extraHeader", "Authorization: Basic " + enc})
	}

	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ALLOW_PROTOCOL=https",
		"GIT_CONFIG_COUNT=" + strconv.Itoa(len(cfg)),
	}
	for i, kv := range cfg {
		env = append(env,
			fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]),
			fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]),
		)
	}
	return env, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// SkipDirs are directory names (matched exactly, at any depth) that WalkFiles
// does not descend into: VCS metadata, installed dependencies and tool caches
// hold manifests that are not the project's own. Build-output-like names
// (packages, build, dist, target, bin, obj) are deliberately not listed, as
// they are real source layouts in many repositories. Callers may extend it
// before walking. Go's vendor/modules.txt is not read by any analyzer, so
// skipping vendor loses nothing.
var SkipDirs = []string{
	".git", "node_modules", "bower_components", "vendor", ".venv", "venv",
	"__pycache__", ".tox", ".terraform", ".yarn", ".pnpm-store",
	// Go's fixture convention: sample manifests there are not the project's own.
	"testdata",
}

func skipDir(name string) bool {
	for _, s := range SkipDirs {
		if s == name {
			return true
		}
	}
	return false
}

// WalkFiles lists the regular files under rootPath, relative to it. Symlinks
// and other special files are skipped so a repository cannot point the
// scanner at files outside the clone. Directories named in SkipDirs are not
// entered (the root itself is always walked).
func (g *LocalGit) WalkFiles(rootPath string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != rootPath && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}
		files = append(files, relPath)
		return nil
	})
	return files, err
}

// MaxManifestBytes caps manifest files read from a clone.
const MaxManifestBytes = 5 << 20

// MaxLockfileBytes caps lockfiles read from a clone. Lockfiles of large
// projects are far bigger than manifests. Parsers may refuse less: the npm
// analyzer does not parse YAML lockfiles over 16 MiB.
const MaxLockfileBytes = 64 << 20

// ReadFile reads a manifest: a regular file at relPath inside rootPath, at
// most MaxManifestBytes long. It fails for symlinks and for any path that
// would resolve outside rootPath.
func (g *LocalGit) ReadFile(rootPath, relPath string) ([]byte, error) {
	return g.ReadFileLimit(rootPath, relPath, MaxManifestBytes)
}

// ReadFileLimit is ReadFile with a caller-chosen size cap.
func (g *LocalGit) ReadFileLimit(rootPath, relPath string, maxBytes int64) ([]byte, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	info, err := root.Lstat(relPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", relPath)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", relPath, maxBytes)
	}
	return root.ReadFile(relPath)
}

// Cleanup removes the cloned repository directory.
func (g *LocalGit) Cleanup(path string) error {
	return os.RemoveAll(path)
}
