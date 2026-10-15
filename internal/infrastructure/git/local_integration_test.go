//go:build integration

package git

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const helloWorld = "https://github.com/octocat/Hello-World"

func TestCloneIntegrationPublicRepo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dest := filepath.Join(t.TempDir(), "repo")
	if err := NewLocalGit().Clone(ctx, CloneOptions{URL: helloWorld, Branch: "master", DestPath: dest, Depth: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "README")); err != nil {
		t.Fatal(err)
	}
}

// GitHub rejects invalid credentials even for public repositories, so a
// failure here proves the Authorization header actually reaches GitHub.
func TestCloneIntegrationSendsToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const bogus = "ghp_orbitIntegrationBogusToken0000000000"
	dest := filepath.Join(t.TempDir(), "repo")
	err := NewLocalGit().Clone(ctx, CloneOptions{URL: helloWorld, Branch: "master", AuthToken: bogus, DestPath: dest, Depth: 1})
	if err == nil {
		t.Fatal("expected GitHub to reject the bogus token")
	}
	if strings.Contains(err.Error(), bogus) {
		t.Fatal("token leaked into the error message")
	}
}
