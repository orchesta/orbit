package entity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ErrInvalidGitHost is returned when a Git host connection is not valid.
var ErrInvalidGitHost = errors.New("invalid git host")

// GitHost is an admin-defined connection to a self-hostable Git service.
// Access tokens are only ever sent to the connection's host.
type GitHost struct {
	ID        uuid.UUID   `json:"id"`
	Kind      GitProvider `json:"kind"` // only azuredevops for now
	Name      string      `json:"name"`
	BaseURL   string      `json:"base_url"` // normalized: no trailing slash
	CreatedAt time.Time   `json:"created_at"`
}

// NewGitHost validates and normalizes a connection.
func NewGitHost(kind GitProvider, name, baseURL string) (*GitHost, error) {
	if kind != GitProviderAzureDevOps {
		return nil, fmt.Errorf("%w: unsupported kind %q", ErrInvalidGitHost, kind)
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 100 {
		return nil, fmt.Errorf("%w: name must be 1-100 characters", ErrInvalidGitHost)
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGitHost, err)
	}
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("%w: scheme must be https", ErrInvalidGitHost)
	case u.Hostname() == "":
		return nil, fmt.Errorf("%w: host is required", ErrInvalidGitHost)
	case !isASCII(u.Host):
		return nil, fmt.Errorf("%w: host must be ASCII", ErrInvalidGitHost)
	case u.User != nil:
		return nil, fmt.Errorf("%w: credentials must not be embedded in the url", ErrInvalidGitHost)
	case strings.ContainsAny(baseURL, "?#"):
		return nil, fmt.Errorf("%w: query and fragment are not allowed", ErrInvalidGitHost)
	}
	rawPath := urlRawPath(baseURL)
	segs, err := pathSegments(baseURL, rawPath, u)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGitHost, err)
	}
	// An absolute host name may carry one trailing dot.
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	switch {
	case host == "dev.azure.com":
		if len(segs) != 1 {
			return nil, fmt.Errorf("%w: dev.azure.com url must be https://dev.azure.com/{organization}", ErrInvalidGitHost)
		}
	case strings.HasSuffix(host, ".visualstudio.com"):
		if len(segs) > 1 {
			return nil, fmt.Errorf("%w: visualstudio.com url may have at most one path segment", ErrInvalidGitHost)
		}
	}
	// ":443" is https's default port: drop it so the same server has one
	// spelling and one credential scope (HostPort).
	hostPort := strings.ToLower(u.Host)
	if u.Port() == "443" {
		hostPort = strings.TrimSuffix(hostPort, ":443")
	}
	baseURL = "https://" + hostPort + rawPath
	return &GitHost{
		ID:        uuid.New(),
		Kind:      kind,
		Name:      name,
		BaseURL:   baseURL,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// HostPort returns the base URL's host including any port, lowercased.
func (h *GitHost) HostPort() string {
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// ValidateHostedRepositoryURL checks raw against a connection's rules: https,
// the connection's host and port, the connection's base path, then
// [Project/]_git/Repo, with no credentials, query or fragment.
func ValidateHostedRepositoryURL(h *GitHost, raw string) error {
	if h == nil {
		return fmt.Errorf("%w: missing connection", ErrInvalidRepositoryURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRepositoryURL, err)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: scheme must be https", ErrInvalidRepositoryURL)
	case u.User != nil:
		return fmt.Errorf("%w: credentials must not be embedded in the url", ErrInvalidRepositoryURL)
	case !isASCII(u.Host) || strings.ToLower(u.Host) != h.HostPort():
		return fmt.Errorf("%w: host must be %s", ErrInvalidRepositoryURL, h.HostPort())
	case strings.ContainsAny(raw, "?#"):
		return fmt.Errorf("%w: query and fragment are not allowed", ErrInvalidRepositoryURL)
	}
	bu, err := url.Parse(h.BaseURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRepositoryURL, err)
	}
	rawPath := urlRawPath(raw)
	if err := checkEncoding(raw, rawPath, u); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRepositoryURL, err)
	}
	prefix := strings.TrimRight(bu.EscapedPath(), "/") + "/"
	if len(rawPath) < len(prefix) || !strings.EqualFold(rawPath[:len(prefix)], prefix) {
		return fmt.Errorf("%w: path must start with %s", ErrInvalidRepositoryURL, prefix)
	}
	rest := strings.Split(rawPath[len(prefix):], "/")
	segs := make([]string, len(rest))
	for i, s := range rest {
		d, err := url.PathUnescape(s)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRepositoryURL, err)
		}
		if err := checkSegment(d); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRepositoryURL, err)
		}
		segs[i] = d
	}
	// Azure DevOps Services also serves {org}.visualstudio.com/DefaultCollection/...
	baseHost := strings.TrimSuffix(strings.ToLower(bu.Hostname()), ".")
	if prefix == "/" && strings.HasSuffix(baseHost, ".visualstudio.com") &&
		len(segs) > 0 && strings.EqualFold(segs[0], "DefaultCollection") {
		segs = segs[1:]
	}
	switch {
	case len(segs) == 3 && segs[1] == "_git":
	case len(segs) == 2 && segs[0] == "_git":
	default:
		return fmt.Errorf("%w: path must be [project/]_git/repository", ErrInvalidRepositoryURL)
	}
	return nil
}

// CanonicalHostedRepositoryURL validates raw against h like
// ValidateHostedRepositoryURL and returns the URL to store: an https URL with
// an explicit default port ":443" loses it, so it matches the connection
// (whose base URL never keeps ":443") and dedupes against the plain spelling.
// The rest of the URL, including its percent-encoding, is kept as written.
func CanonicalHostedRepositoryURL(h *GitHost, raw string) (string, error) {
	if u, err := url.Parse(raw); err == nil && u.Scheme == "https" && u.Port() == "443" {
		if i := strings.Index(raw, "://"); i >= 0 {
			rest := raw[i+3:]
			end := strings.IndexAny(rest, "/?#")
			if end < 0 {
				end = len(rest)
			}
			if authority := rest[:end]; strings.HasSuffix(authority, ":443") {
				raw = raw[:i+3] + strings.TrimSuffix(authority, ":443") + rest[end:]
			}
		}
	}
	if err := ValidateHostedRepositoryURL(h, raw); err != nil {
		return "", err
	}
	return raw, nil
}

// checkSegment rejects empty, dot and separator-bearing path segments.
func checkSegment(seg string) error {
	if seg == "" || seg == "." || seg == ".." {
		return errors.New("path must not contain empty, . or .. segments")
	}
	if !utf8.ValidString(seg) {
		return errors.New("path segment is not valid UTF-8")
	}
	for _, r := range seg {
		if r == '/' || r == '\\' || unicode.IsControl(r) {
			return errors.New("path segment contains a forbidden character")
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// urlRawPath returns the path of an absolute URL exactly as written, without
// query or fragment (callers reject those before relying on this).
func urlRawPath(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	j := strings.Index(rest, "/")
	if j < 0 {
		return ""
	}
	return rest[j:]
}

// checkEncoding enforces the URL encoding rules shared by connection and
// repository URLs. Encoded separators, dots and "%" are never legitimate in
// Azure names and are how traversal gets smuggled past segment checks; raw
// characters that need escaping would make one repository spell two ways.
func checkEncoding(raw, rawPath string, u *url.URL) error {
	lower := strings.ToLower(raw)
	for _, bad := range []string{"%25", "%2f", "%5c", "%2e"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("path must not contain %s", strings.ToUpper(bad))
		}
	}
	if u.EscapedPath() != rawPath {
		return errors.New("path contains characters that must be percent-encoded")
	}
	// Encoding an unreserved character (RFC 3986: ALPHA, DIGIT, "-", ".",
	// "_", "~") only spells the same path a second way, e.g. %5Fgit for _git.
	for i := 0; i+2 < len(rawPath); i++ {
		if rawPath[i] != '%' {
			continue
		}
		if c, ok := unhex2(rawPath[i+1], rawPath[i+2]); ok && isUnreserved(c) {
			return fmt.Errorf("path must not percent-encode %q (%s)", c, rawPath[i:i+3])
		}
	}
	return nil
}

// unhex2 decodes two hex digits.
func unhex2(hi, lo byte) (byte, bool) {
	h, ok1 := unhex(hi)
	l, ok2 := unhex(lo)
	return h<<4 | l, ok1 && ok2
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// isUnreserved reports whether c is an RFC 3986 unreserved character.
func isUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// pathSegments checks a URL's path with checkEncoding and returns its decoded
// segments (none for an empty path).
func pathSegments(raw, rawPath string, u *url.URL) ([]string, error) {
	if err := checkEncoding(raw, rawPath, u); err != nil {
		return nil, err
	}
	trimmed := strings.TrimPrefix(rawPath, "/")
	if trimmed == "" {
		return nil, nil
	}
	parts := strings.Split(trimmed, "/")
	segs := make([]string, len(parts))
	for i, p := range parts {
		d, err := url.PathUnescape(p)
		if err != nil {
			return nil, err
		}
		if err := checkSegment(d); err != nil {
			return nil, err
		}
		segs[i] = d
	}
	return segs, nil
}
