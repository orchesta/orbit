package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	gitprovider "github.com/aligoren/orbit/internal/infrastructure/git"
	"github.com/aligoren/orbit/internal/infrastructure/httpclient"
)

// Ensure interface compliance at compile time.
var _ gitprovider.Provider = (*Client)(nil)

// Client implements git.Provider for GitHub.
type Client struct {
	httpClient *http.Client
	localGit   *gitprovider.LocalGit
	baseURL    string
}

// NewClient creates a new GitHub client.
func NewClient() *Client {
	return &Client{
		httpClient: httpclient.New(30 * time.Second),
		localGit:   gitprovider.NewLocalGit(),
		baseURL:    "https://api.github.com",
	}
}

// Clone clones a GitHub repository to the given local path.
func (c *Client) Clone(ctx context.Context, opts gitprovider.CloneOptions) error {
	return c.localGit.Clone(ctx, opts)
}

// ListFiles lists files in a GitHub repository using the API.
func (c *Client) ListFiles(ctx context.Context, opts gitprovider.ListFilesOptions) ([]string, error) {
	owner, repo, err := parseGitHubURL(opts.RepoURL)
	if err != nil {
		return nil, err
	}

	ref := opts.Branch
	if ref == "" {
		ref = "main"
	}

	// Use the Git Trees API with recursive flag
	url := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", c.baseURL, owner, repo, ref)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if opts.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.AuthToken)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var files []string
	for _, item := range result.Tree {
		if item.Type == "blob" {
			files = append(files, item.Path)
		}
	}

	return files, nil
}

// GetFileContent retrieves the content of a file from a GitHub repository.
func (c *Client) GetFileContent(ctx context.Context, opts gitprovider.GetFileContentOptions) ([]byte, error) {
	owner, repo, err := parseGitHubURL(opts.RepoURL)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, repo, opts.FilePath)
	if opts.Branch != "" {
		url += "?ref=" + opts.Branch
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if opts.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.AuthToken)
	}
	// Request raw content
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// parseGitHubURL extracts owner and repo from a GitHub URL.
func parseGitHubURL(rawURL string) (owner, repo string, err error) {
	// Handle formats:
	// https://github.com/owner/repo
	// https://github.com/owner/repo.git
	var parts []string

	prefixes := []string{"https://github.com/", "http://github.com/"}
	for _, prefix := range prefixes {
		if len(rawURL) > len(prefix) && rawURL[:len(prefix)] == prefix {
			trimmed := rawURL[len(prefix):]
			// Remove trailing .git
			if len(trimmed) > 4 && trimmed[len(trimmed)-4:] == ".git" {
				trimmed = trimmed[:len(trimmed)-4]
			}
			// Remove trailing slash
			if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '/' {
				trimmed = trimmed[:len(trimmed)-1]
			}
			// Split by /
			for i, j := 0, 0; j <= len(trimmed); j++ {
				if j == len(trimmed) || trimmed[j] == '/' {
					if j > i {
						parts = append(parts, trimmed[i:j])
					}
					i = j + 1
				}
			}
			break
		}
	}

	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub URL: %s", rawURL)
	}

	return parts[0], parts[1], nil
}

// ListRepositories lists all repositories accessible by the given token.
// It fetches user repos and all organization repos, deduplicating by full name.
func (c *Client) ListRepositories(ctx context.Context, token string) ([]gitprovider.RepoInfo, error) {
	seen := make(map[string]bool)
	var allRepos []gitprovider.RepoInfo

	// 1. Fetch user repos (paginated)
	page := 1
	for {
		url := fmt.Sprintf("%s/user/repos?per_page=100&sort=updated&page=%d&affiliation=owner,collaborator,organization_member", c.baseURL, page)
		repos, err := c.fetchRepoPage(ctx, url, token)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch user repos (page %d): %w", page, err)
		}
		for _, r := range repos {
			if !seen[r.FullName] {
				seen[r.FullName] = true
				allRepos = append(allRepos, r)
			}
		}
		if len(repos) < 100 {
			break
		}
		page++
	}

	return allRepos, nil
}

// fetchRepoPage fetches a single page of repositories from a GitHub API URL.
func (c *Client) fetchRepoPage(ctx context.Context, url, token string) ([]gitprovider.RepoInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var ghRepos []struct {
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		HTMLURL       string `json:"html_url"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
		Description   string `json:"description"`
		Language      string `json:"language"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghRepos); err != nil {
		return nil, fmt.Errorf("failed to decode repos: %w", err)
	}

	result := make([]gitprovider.RepoInfo, len(ghRepos))
	for i, r := range ghRepos {
		result[i] = gitprovider.RepoInfo{
			Name:          r.Name,
			FullName:      r.FullName,
			URL:           r.HTMLURL,
			DefaultBranch: r.DefaultBranch,
			IsPrivate:     r.Private,
			Description:   r.Description,
			Language:      r.Language,
		}
	}
	return result, nil
}
