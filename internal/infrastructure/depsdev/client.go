// Package depsdev looks up package licenses on deps.dev (Open Source
// Insights), which serves the licenses that npm, PyPI and NuGet packages
// declare and that it detects for Go modules, as SPDX expressions.
//
// Every lookup sends the package's ecosystem, name and version to
// api.deps.dev, a Google service; nothing else about the scanned project is
// sent. Use of the API is subject to the Google API Terms of Service, which
// expressly permit caching.
package depsdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/httpclient"
	"github.com/orchesta/orbit/internal/spdx"
)

const (
	apiURL = "https://api.deps.dev/v3"
	// maxBodyBytes caps a GetVersion response; real ones are a few KB.
	maxBodyBytes = 1 << 20
	// cacheTTL is how long an answer is reused. The licenses of a
	// published version rarely change.
	cacheTTL = 24 * time.Hour
	// maxCacheEntries bounds the cache; it is emptied when full.
	maxCacheEntries = 100_000
)

// systems maps Orbit's ecosystems to deps.dev's system names.
var systems = map[entity.Ecosystem]string{
	entity.EcosystemNpm:   "npm",
	entity.EcosystemPyPI:  "pypi",
	entity.EcosystemNuGet: "nuget",
	entity.EcosystemGo:    "go",
}

// Client looks up licenses on deps.dev. It is safe for concurrent use and
// caches answers, including "unknown", for cacheTTL.
type Client struct {
	httpClient *http.Client
	baseURL    string
	retryDelay time.Duration
	now        func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	license string
	at      time.Time
}

// NewClient returns a client for api.deps.dev with a 15 second timeout per
// request.
func NewClient() *Client {
	return &Client{
		httpClient: httpclient.New(15 * time.Second),
		baseURL:    apiURL,
		retryDelay: time.Second,
		now:        time.Now,
		cache:      make(map[string]cached),
	}
}

// License returns the license of one package version as a normalised SPDX
// expression (several licenses are joined with AND, since deps.dev does not
// say how they relate). It returns "" and no error when deps.dev does not
// know the version, has no license for it, or has only "non-standard"
// licenses, and for an ecosystem deps.dev does not cover. An error means
// the lookup itself failed (network, rate limit, server error, bad
// response); a 429 or 5xx response is retried once.
func (c *Client) License(ctx context.Context, eco entity.Ecosystem, name, version string) (string, error) {
	system, ok := systems[eco]
	if !ok || name == "" || version == "" {
		return "", nil
	}
	if eco == entity.EcosystemGo && !strings.HasPrefix(version, "v") {
		version = "v" + version // the Go analyzer drops the "v"
	}
	key := system + "\x00" + name + "\x00" + version
	if lic, ok := c.cached(key); ok {
		return lic, nil
	}
	reqURL := c.baseURL + "/systems/" + system + "/packages/" + url.PathEscape(name) + "/versions/" + url.PathEscape(version)
	lic, err := c.fetch(ctx, reqURL)
	var status statusError
	if errors.As(err, &status) && status.retryable() {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(c.retryDelay):
		}
		lic, err = c.fetch(ctx, reqURL)
	}
	if err != nil {
		return "", fmt.Errorf("deps.dev %s %s@%s: %w", system, name, version, err)
	}
	c.store(key, lic)
	return lic, nil
}

type statusError int

func (e statusError) Error() string   { return fmt.Sprintf("unexpected status %d", int(e)) }
func (e statusError) retryable() bool { return e == http.StatusTooManyRequests || e >= 500 }

func (c *Client) fetch(ctx context.Context, reqURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		return "", nil // not a version deps.dev knows: private or unpublished
	case resp.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		return "", statusError(resp.StatusCode)
	}
	var body struct {
		Licenses []string `json:"licenses"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&body); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return spdx.Join(body.Licenses), nil
}

func (c *Client) cached(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || c.now().Sub(e.at) >= cacheTTL {
		return "", false
	}
	return e.license, true
}

func (c *Client) store(key, license string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= maxCacheEntries {
		clear(c.cache)
	}
	c.cache[key] = cached{license: license, at: c.now()}
}
