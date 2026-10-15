package azuredevops

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
	gitprovider "github.com/orchesta/orbit/internal/infrastructure/git"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

func fixture(t *testing.T, name, host string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "{{HOST}}", host)
}

// newTestClient returns a client that trusts srv's certificate.
func newTestClient(srv *httptest.Server) *Client {
	return newClient(srv.Client())
}

func hostFor(srv *httptest.Server, path string) *entity.GitHost {
	return &entity.GitHost{Kind: entity.GitProviderAzureDevOps, Name: "t", BaseURL: srv.URL + path}
}

func TestListRepositories_Services(t *testing.T) {
	var gotPath, gotVersion, gotAuth, gotAccept string
	var hp string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotVersion = r.URL.Path, r.URL.Query().Get("api-version")
		gotAuth, gotAccept = r.Header.Get("Authorization"), r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(fixture(t, "services.json", hp)))
	}))
	defer srv.Close()
	hp = strings.TrimPrefix(srv.URL, "https://")

	repos, skipped, err := newTestClient(srv).ListRepositories(context.Background(), hostFor(srv, "/org"), "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/org/_apis/git/repositories" || gotVersion != "5.0" {
		t.Errorf("path/version = %q %q", gotPath, gotVersion)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":s3cret")); gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	want := []gitprovider.RepoInfo{
		{Name: "Repo Y", FullName: "Project X/Repo Y", URL: "https://" + hp + "/org/Project%20X/_git/Repo%20Y", DefaultBranch: "main", IsPrivate: true},
		{Name: "empty", FullName: "Project X/empty", URL: "https://" + hp + "/org/Project%20X/_git/empty", DefaultBranch: "", IsPrivate: true},
		{Name: "oss", FullName: "Open/oss", URL: "https://" + hp + "/org/Open/_git/oss", DefaultBranch: "develop", IsPrivate: false},
	}
	if len(repos) != len(want) {
		t.Fatalf("got %d repos %+v, want %d (disabled and foreign-host repos skipped)", len(repos), repos, len(want))
	}
	// Only the foreign-host repository counts: disabled ones are not usable
	// anywhere, so leaving them out needs no explanation.
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the foreign-host repository)", skipped)
	}
	for i := range want {
		if repos[i] != want[i] {
			t.Errorf("repo %d = %+v, want %+v", i, repos[i], want[i])
		}
		if strings.Contains(repos[i].URL, "@") {
			t.Errorf("repo %d url carries userinfo: %s", i, repos[i].URL)
		}
	}
}

func TestListRepositories_Server(t *testing.T) {
	var srv *httptest.Server
	var gotPath string
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture(t, "server.json", strings.TrimPrefix(srv.URL, "https://"))))
	}))
	defer srv.Close()
	repos, skipped, err := newTestClient(srv).ListRepositories(context.Background(), hostFor(srv, "/tfs/Col"), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if gotPath != "/tfs/Col/_apis/git/repositories" {
		t.Errorf("path = %q", gotPath)
	}
	if len(repos) != 1 || repos[0].FullName != "Project/Repo" || repos[0].DefaultBranch != "master" ||
		repos[0].URL != srv.URL+"/tfs/Col/Project/_git/Repo" || !repos[0].IsPrivate {
		t.Errorf("repos = %+v", repos)
	}
}

// A connection whose URL does not match the organization's (e.g. the
// visualstudio.com form for an organization served on dev.azure.com) skips
// every repository; the count tells the caller why the list is empty.
func TestListRepositories_AllSkippedAreCounted(t *testing.T) {
	var hp string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture(t, "services.json", hp)))
	}))
	defer srv.Close()
	hp = strings.TrimPrefix(srv.URL, "https://")
	// The API answers under /other, but the repositories live under /org.
	repos, skipped, err := newTestClient(srv).ListRepositories(context.Background(), hostFor(srv, "/other"), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 0 || skipped != 4 {
		t.Fatalf("repos = %+v, skipped = %d; want none and 4 skipped (the disabled one is not counted)", repos, skipped)
	}
}

// rewriteTo sends every request to srv, whatever host the URL names.
type rewriteTo struct {
	srv  *httptest.Server
	base http.RoundTripper
}

func (rt rewriteTo) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Host = strings.TrimPrefix(rt.srv.URL, "https://")
	return rt.base.RoundTrip(r)
}

// An Azure DevOps Server whose public URL includes ":443" reports webUrls with
// it. They are mapped to the canonical URL (no ":443"), which matches the
// connection, instead of being skipped.
func TestListRepositories_DefaultPortIsCanonicalized(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[
			{"name":"R","webUrl":"https://tfs.example.com:443/tfs/Col/P/_git/R","defaultBranch":"refs/heads/main","project":{"name":"P"}},
			{"name":"S","remoteUrl":"https://tfs.example.com:443/tfs/Col/P/_git/S","project":{"name":"P"}}
		]}`))
	}))
	defer srv.Close()
	hc := *srv.Client()
	hc.Transport = rewriteTo{srv: srv, base: srv.Client().Transport}
	host, err := entity.NewGitHost(entity.GitProviderAzureDevOps, "t", "https://tfs.example.com:443/tfs/Col")
	if err != nil {
		t.Fatal(err)
	}
	repos, skipped, err := newClient(&hc).ListRepositories(context.Background(), host, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 || len(repos) != 2 {
		t.Fatalf("repos = %+v, skipped = %d; want both repositories, none skipped", repos, skipped)
	}
	if repos[0].URL != "https://tfs.example.com/tfs/Col/P/_git/R" || repos[1].URL != "https://tfs.example.com/tfs/Col/P/_git/S" {
		t.Fatalf("urls = %q, %q; want them without :443", repos[0].URL, repos[1].URL)
	}
}

func TestListRepositories_ErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		unauth      bool
	}{
		{"203 html sign-in page", 203, "text/html", "<html>sign in</html>", true},
		{"200 html sign-in page", 200, "text/html", "<html>sign in</html>", true},
		{"203 json", 203, "application/json", `{"value":[]}`, true},
		{"401", 401, "application/json", `{"message":"nope"}`, true},
		{"403", 403, "application/json", `{"message":"nope"}`, true},
		{"500", 500, "text/plain", strings.Repeat("x", 2000), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			_, _, err := newTestClient(srv).ListRepositories(context.Background(), hostFor(srv, "/org"), "tok")
			if err == nil {
				t.Fatal("expected error")
			}
			if got := errors.Is(err, ErrUnauthorized); got != tt.unauth {
				t.Errorf("errors.Is(ErrUnauthorized) = %v, want %v (err: %v)", got, tt.unauth, err)
			}
			if !tt.unauth {
				if !strings.Contains(err.Error(), "500") {
					t.Errorf("error lacks status code: %v", err)
				}
				const prefix = "Azure DevOps API error (status 500): "
				if body := strings.TrimPrefix(err.Error(), prefix); len(body) != 512 {
					t.Errorf("error body = %d bytes, want exactly 512", len(body))
				}
			}
		})
	}
}

func TestListRepositories_CrossHostRedirectRefused(t *testing.T) {
	var leaked atomic.Bool
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "example.com") {
			// The redirect target: it must never be reached with credentials.
			if r.Header.Get("Authorization") != "" {
				leaked.Store(true)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":[]}`))
			return
		}
		port := srv.URL[strings.LastIndex(srv.URL, ":"):]
		http.Redirect(w, r, "https://example.com"+port+"/org/_apis/git/repositories", http.StatusFound)
	}))
	defer srv.Close()

	// example.com is in httptest's certificate; dial everything to the one server.
	tr := srv.Client().Transport.(*http.Transport).Clone()
	addr := strings.TrimPrefix(srv.URL, "https://")
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	base := &http.Client{Transport: tr}
	c := newClient(base)

	_, _, err := c.ListRepositories(context.Background(), hostFor(srv, "/org"), "tok")
	if err == nil {
		t.Fatal("expected an error for a cross-host redirect")
	}
	if leaked.Load() {
		t.Fatal("Authorization reached the redirect target")
	}
}

func TestNewClient_RefusesCrossHostRedirect(t *testing.T) {
	c := NewClient()
	from, _ := http.NewRequest("GET", "https://dev.azure.com/org", nil)
	to, _ := http.NewRequest("GET", "https://evil.example.com/x", nil)
	if err := c.http.CheckRedirect(to, []*http.Request{from}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("cross-host redirect err = %v, want ErrUseLastResponse", err)
	}
	port, _ := http.NewRequest("GET", "https://dev.azure.com:8443/x", nil)
	if err := c.http.CheckRedirect(port, []*http.Request{from}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("cross-port redirect err = %v, want ErrUseLastResponse", err)
	}
	same, _ := http.NewRequest("GET", "https://dev.azure.com/other", nil)
	if err := c.http.CheckRedirect(same, []*http.Request{from}); err != nil {
		t.Errorf("same-host redirect err = %v, want nil", err)
	}
}

func TestListRepositories_CrossPortRedirectRefused(t *testing.T) {
	var reached, leaked atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer target.Close()
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/org/_apis/git/repositories?api-version=5.0", http.StatusFound)
	}))
	defer src.Close()

	_, _, err := newTestClient(src).ListRepositories(context.Background(), hostFor(src, "/org"), "tok")
	if err == nil {
		t.Fatal("expected an error for a cross-port redirect")
	}
	if reached.Load() || leaked.Load() {
		t.Fatalf("redirect target reached=%v leaked=%v", reached.Load(), leaked.Load())
	}
}
