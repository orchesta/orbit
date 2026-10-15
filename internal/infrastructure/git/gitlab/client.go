package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	gitprovider "github.com/orchesta/orbit/internal/infrastructure/git"
	"github.com/orchesta/orbit/internal/infrastructure/httpclient"
)

// Ensure interface compliance at compile time.
var _ gitprovider.Provider = (*Client)(nil)

// Client implements git.Provider for GitLab.
type Client struct {
	httpClient *http.Client
	localGit   *gitprovider.LocalGit
	baseURL    string
}

// NewClient creates a new GitLab client.
func NewClient() *Client {
	return &Client{
		httpClient: httpclient.New(30 * time.Second),
		localGit:   gitprovider.NewLocalGit(),
		baseURL:    "https://gitlab.com/api/v4",
	}
}

// Clone clones a GitLab repository to the given local path.
func (c *Client) Clone(ctx context.Context, opts gitprovider.CloneOptions) error {
	return c.localGit.Clone(ctx, opts)
}

// ListFiles lists files in a GitLab repository using the Repository Tree API.
func (c *Client) ListFiles(ctx context.Context, opts gitprovider.ListFilesOptions) ([]string, error) {
	projectPath, err := parseGitLabURL(opts.RepoURL)
	if err != nil {
		return nil, err
	}

	encodedPath := url.PathEscape(projectPath)
	ref := opts.Branch
	if ref == "" {
		ref = "main"
	}

	var allFiles []string
	page := 1
	perPage := 100

	for {
		apiURL := fmt.Sprintf("%s/projects/%s/repository/tree?ref=%s&recursive=true&per_page=%d&page=%d",
			c.baseURL, encodedPath, url.QueryEscape(ref), perPage, page)

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		if opts.AuthToken != "" {
			req.Header.Set("PRIVATE-TOKEN", opts.AuthToken)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to list files: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("GitLab API error (status %d): %s", resp.StatusCode, string(body))
		}

		var items []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		for _, item := range items {
			if item.Type == "blob" {
				allFiles = append(allFiles, item.Path)
			}
		}

		// Check if there are more pages
		if len(items) < perPage {
			break
		}
		page++
	}

	return allFiles, nil
}

// GetFileContent retrieves the content of a file from a GitLab repository.
func (c *Client) GetFileContent(ctx context.Context, opts gitprovider.GetFileContentOptions) ([]byte, error) {
	projectPath, err := parseGitLabURL(opts.RepoURL)
	if err != nil {
		return nil, err
	}

	encodedProject := url.PathEscape(projectPath)
	encodedFile := url.PathEscape(opts.FilePath)

	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s/raw", c.baseURL, encodedProject, encodedFile)
	if opts.Branch != "" {
		apiURL += "?ref=" + url.QueryEscape(opts.Branch)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if opts.AuthToken != "" {
		req.Header.Set("PRIVATE-TOKEN", opts.AuthToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitLab API error (status %d): %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// parseGitLabURL extracts the project path from a GitLab URL.
func parseGitLabURL(rawURL string) (string, error) {
	// Handle formats:
	// https://gitlab.com/group/project
	// https://gitlab.com/group/subgroup/project
	// https://gitlab.com/group/project.git
	prefixes := []string{"https://gitlab.com/", "http://gitlab.com/"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(rawURL, prefix) {
			path := strings.TrimPrefix(rawURL, prefix)
			path = strings.TrimSuffix(path, ".git")
			path = strings.TrimSuffix(path, "/")
			if path == "" {
				return "", fmt.Errorf("invalid GitLab URL: %s", rawURL)
			}
			return path, nil
		}
	}
	return "", fmt.Errorf("invalid GitLab URL: %s", rawURL)
}

// ListRepositories lists all projects accessible by the given token using the GitLab Projects API.
func (c *Client) ListRepositories(ctx context.Context, token string) ([]gitprovider.RepoInfo, error) {
	var allRepos []gitprovider.RepoInfo
	page := 1

	for {
		apiURL := fmt.Sprintf("%s/projects?membership=true&per_page=100&order_by=updated_at&sort=desc&page=%d",
			c.baseURL, page)

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("PRIVATE-TOKEN", token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch GitLab projects: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("GitLab API error (status %d): %s", resp.StatusCode, string(body))
		}

		var glProjects []struct {
			Name              string `json:"name"`
			PathWithNamespace string `json:"path_with_namespace"`
			WebURL            string `json:"web_url"`
			DefaultBranch     string `json:"default_branch"`
			Visibility        string `json:"visibility"` // "private", "internal", "public"
			Description       string `json:"description"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&glProjects); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode GitLab projects: %w", err)
		}
		resp.Body.Close()

		for _, p := range glProjects {
			allRepos = append(allRepos, gitprovider.RepoInfo{
				Name:          p.Name,
				FullName:      p.PathWithNamespace,
				URL:           p.WebURL,
				DefaultBranch: p.DefaultBranch,
				IsPrivate:     p.Visibility != "public",
				Description:   p.Description,
			})
		}

		if len(glProjects) < 100 {
			break
		}
		page++
	}

	return allRepos, nil
}
