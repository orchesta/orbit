package git

import (
	"context"
)

// RepoInfo holds metadata about a remote repository discovered via the provider API.
type RepoInfo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	URL           string `json:"url"`
	DefaultBranch string `json:"default_branch"`
	IsPrivate     bool   `json:"is_private"`
	Description   string `json:"description"`
	Language      string `json:"language"`
}

// Provider defines operations for interacting with a Git hosting service.
type Provider interface {
	// Clone clones a repository to the given local path.
	Clone(ctx context.Context, opts CloneOptions) error

	// ListFiles lists all files in a repository. Used for manifest discovery.
	ListFiles(ctx context.Context, opts ListFilesOptions) ([]string, error)

	// GetFileContent retrieves the content of a file from a repository.
	GetFileContent(ctx context.Context, opts GetFileContentOptions) ([]byte, error)

	// ListRepositories lists all repositories accessible by the given token.
	ListRepositories(ctx context.Context, token string) ([]RepoInfo, error)
}

// CloneOptions holds options for cloning a repository.
type CloneOptions struct {
	URL       string
	Branch    string
	AuthToken string
	DestPath  string
	Depth     int // Shallow clone depth, 0 for full clone

	// Credential, when set, replaces AuthToken: the token is sent only to the
	// credential's own host (port included) and to no other.
	Credential *Credential
}

// Credential scopes a token to one host (host[:port], lowercased).
type Credential struct {
	HostPort string
	Username string
	Token    string
}

// Cloner is what scans need from a provider.
type Cloner interface {
	Clone(ctx context.Context, opts CloneOptions) error
}

// ListFilesOptions holds options for listing files.
type ListFilesOptions struct {
	RepoURL   string
	Branch    string
	AuthToken string
	Path      string // Subdirectory path, empty for root
}

// GetFileContentOptions holds options for getting file content.
type GetFileContentOptions struct {
	RepoURL   string
	Branch    string
	AuthToken string
	FilePath  string
}
