// Package azuredevops lists repositories through the Azure DevOps REST API,
// for both Azure DevOps Services and Azure DevOps Server.
package azuredevops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	gitprovider "github.com/aligoren/orbit/internal/infrastructure/git"
	"github.com/aligoren/orbit/internal/infrastructure/httpclient"
)

// ErrUnauthorized means Azure DevOps did not accept the token. Azure DevOps
// often answers a bad token with a 203 or a 200 HTML sign-in page instead of
// a 401, so those are reported the same way.
var ErrUnauthorized = errors.New("azure devops rejected the token")

const (
	apiVersion   = "5.0"
	maxErrorBody = 512
	maxRedirects = 10
)

// Client talks to the Azure DevOps REST API.
type Client struct {
	http *http.Client
}

// NewClient creates a client that refuses redirects to another host.
func NewClient() *Client {
	return newClient(httpclient.New(30 * time.Second))
}

// newClient copies base and installs the redirect policy, leaving the
// caller's client untouched.
func newClient(base *http.Client) *Client {
	c := *base
	c.CheckRedirect = refuseCrossHostRedirect
	return &Client{http: &c}
}

// refuseCrossHostRedirect stops the Authorization header from following a
// redirect to another host (or down to plain http). Returning
// http.ErrUseLastResponse hands the 3xx back, which ListRepositories reports
// as an error.
func refuseCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("stopped after too many redirects")
	}
	first := via[0].URL
	if !strings.EqualFold(req.URL.Host, first.Host) || req.URL.Scheme != "https" {
		return http.ErrUseLastResponse
	}
	return nil
}

type repository struct {
	Name          string `json:"name"`
	WebURL        string `json:"webUrl"`
	RemoteURL     string `json:"remoteUrl"`
	DefaultBranch string `json:"defaultBranch"`
	IsDisabled    bool   `json:"isDisabled"`
	Project       struct {
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	} `json:"project"`
}

// ListRepositories lists the repositories the token can see on the host.
// Disabled repositories and repositories whose URL does not belong to the
// connection are left out; skipped counts the latter, which point at a
// connection URL that does not match the organization's.
func (c *Client) ListRepositories(ctx context.Context, host *entity.GitHost, token string) ([]gitprovider.RepoInfo, int, error) {
	endpoint := host.BaseURL + "/_apis/git/repositories?api-version=" + apiVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+token)))
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusNonAuthoritativeInfo:
		return nil, 0, ErrUnauthorized
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, 0, fmt.Errorf("Azure DevOps API error (status %d): %s", resp.StatusCode, string(body))
	case !isJSON(resp.Header.Get("Content-Type")):
		return nil, 0, ErrUnauthorized
	}

	var payload struct {
		Value []repository `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, 0, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := make([]gitprovider.RepoInfo, 0, len(payload.Value))
	skipped := 0
	for _, r := range payload.Value {
		if r.IsDisabled {
			continue
		}
		repoURL, err := cleanURL(r.WebURL, r.RemoteURL)
		if err == nil {
			// A server whose public URL includes ":443" reports it; the
			// canonical URL drops it so it matches the connection.
			var canonical string
			if canonical, err = entity.CanonicalHostedRepositoryURL(host, repoURL); err == nil {
				repoURL = canonical
			}
		}
		if err != nil {
			// repoURL is empty when cleanURL failed; otherwise it carries no userinfo.
			slog.Warn("skipping azure devops repository with unusable url", "repository", r.Name, "url", repoURL, "base_url", host.BaseURL, "error", err)
			skipped++
			continue
		}
		repos = append(repos, gitprovider.RepoInfo{
			Name:          r.Name,
			FullName:      r.Project.Name + "/" + r.Name,
			URL:           repoURL,
			DefaultBranch: strings.TrimPrefix(r.DefaultBranch, "refs/heads/"),
			IsPrivate:     r.Project.Visibility != "public",
		})
	}
	return repos, skipped, nil
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// cleanURL returns webUrl, or remoteUrl when webUrl is absent, without
// userinfo.
func cleanURL(webURL, remoteURL string) (string, error) {
	raw := webURL
	if raw == "" {
		raw = remoteURL
	}
	if raw == "" {
		return "", errors.New("repository has no url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.User = nil
	return u.String(), nil
}
