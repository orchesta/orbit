package entity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// GitProvider represents a supported Git hosting provider.
type GitProvider string

const (
	GitProviderGitHub GitProvider = "github"
	GitProviderGitLab GitProvider = "gitlab"
	// GitProviderAzureDevOps covers Azure DevOps Services and Server. Its hosts
	// are not fixed, so repositories need a GitHost connection.
	GitProviderAzureDevOps GitProvider = "azuredevops"
)

// KnownProvider reports whether p is a supported provider.
func KnownProvider(p GitProvider) bool {
	switch p {
	case GitProviderGitHub, GitProviderGitLab, GitProviderAzureDevOps:
		return true
	}
	return false
}

// ErrInvalidRepositoryURL is returned when a repository URL is not a plain
// https URL on its provider's host.
var ErrInvalidRepositoryURL = errors.New("invalid repository url")

// providerHosts lists the only host each provider's repositories may live on.
// Access tokens are sent to these hosts, so they must never be user-chosen.
var providerHosts = map[GitProvider]string{
	GitProviderGitHub: "github.com",
	GitProviderGitLab: "gitlab.com",
}

// Host returns the host that repositories of this provider are served from.
func (p GitProvider) Host() (string, bool) {
	host, ok := providerHosts[p]
	return host, ok
}

// ValidateRepositoryURL checks that raw is an https URL on the provider's host
// with an owner/repo path and no credentials, query or fragment.
func ValidateRepositoryURL(provider GitProvider, raw string) error {
	if provider == GitProviderAzureDevOps {
		return fmt.Errorf("%w: azure devops repositories need a connection", ErrInvalidRepositoryURL)
	}
	host, ok := provider.Host()
	if !ok {
		return fmt.Errorf("%w: unsupported provider %q", ErrInvalidRepositoryURL, provider)
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
	case !strings.EqualFold(u.Host, host):
		return fmt.Errorf("%w: host must be %s for provider %s", ErrInvalidRepositoryURL, host, provider)
	case u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%w: query and fragment are not allowed", ErrInvalidRepositoryURL)
	case !strings.Contains(strings.Trim(u.Path, "/"), "/"):
		return fmt.Errorf("%w: path must be owner/repository", ErrInvalidRepositoryURL)
	}
	// Provider owner and repository names never contain "%", so any
	// percent-encoding is rejected; that also covers double encoding such as
	// "%252e%252e", which a later decode would turn into "..".
	if strings.Contains(u.EscapedPath(), "%") {
		return fmt.Errorf("%w: path must not be percent-encoded", ErrInvalidRepositoryURL)
	}
	// u.Path is percent-decoded, so "%2e%2e" shows up as "..".
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: path must not contain . or .. segments", ErrInvalidRepositoryURL)
		}
	}
	return nil
}

// Repository represents a Git repository to be scanned for dependencies.
type Repository struct {
	ID            uuid.UUID   `json:"id"`
	Name          string      `json:"name"`
	URL           string      `json:"url"`
	Provider      GitProvider `json:"provider"`
	DefaultBranch string      `json:"default_branch"`
	Schedule      string      `json:"schedule"` // Cron expression
	AuthToken     string      `json:"-"`        // Encrypted, never serialized
	GitHostID     *uuid.UUID  `json:"git_host_id,omitempty"`
	IsActive      bool        `json:"is_active"`
	LastScannedAt *time.Time  `json:"last_scanned_at,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// NewRepository creates a new Repository with sensible defaults.
func NewRepository(name, url string, provider GitProvider, authToken string) *Repository {
	now := time.Now().UTC()
	return &Repository{
		ID:            uuid.New(),
		Name:          name,
		URL:           url,
		Provider:      provider,
		DefaultBranch: "main",
		Schedule:      "0 */6 * * *", // Every 6 hours
		AuthToken:     authToken,
		IsActive:      true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// NormalizeRepositoryURL lowercases a repository URL and drops trailing
// slashes and ".git", so the same repository compares equal however it was
// typed. It must stay in step with the SQL in RepositoryPostgresRepo.ExistingURLs.
func NormalizeRepositoryURL(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimRight(s, "/")
	return strings.TrimSuffix(s, ".git")
}
