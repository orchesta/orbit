//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/domain/repository"
)

func TestExistingURLsMatchesNormalized(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	newQueueRepo(t, ctx, pool, "Alpha") // stored as https://github.com/o/Alpha

	got, err := repos.ExistingURLs(ctx, []string{"https://github.com/o/alpha.git", "https://github.com/o/beta"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["https://github.com/o/alpha"] || got["https://github.com/o/beta"] {
		t.Fatalf("ExistingURLs = %v", got)
	}

	// Several trailing slashes (and stray whitespace) normalize the same in Go and SQL.
	gamma := entity.NewRepository("Gamma", " https://github.com/o/Gamma.git// ", entity.GitProviderGitHub, "")
	if err := repos.Create(ctx, gamma, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err = repos.ExistingURLs(ctx, []string{"https://github.com/o/gamma//"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["https://github.com/o/gamma"] {
		t.Fatalf("ExistingURLs with // = %v", got)
	}

	// Tabs and newlines trim too, matching Go's TrimSpace.
	zeta := entity.NewRepository("Zeta", "\t https://github.com/o/Zeta.git\n", entity.GitProviderGitHub, "")
	if err := repos.Create(ctx, zeta, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, err = repos.ExistingURLs(ctx, []string{"\n https://github.com/o/zeta\t"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["https://github.com/o/zeta"] {
		t.Fatalf("ExistingURLs with tab/newline = %v", got)
	}
}

func TestCreateStoresGivenNextScanAt(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	want := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Microsecond)
	r := entity.NewRepository("Delta", "https://github.com/o/Delta", entity.GitProviderGitHub, "")
	if err := repos.Create(ctx, r, want); err != nil {
		t.Fatal(err)
	}
	var got time.Time
	if err := pool.QueryRow(ctx, "SELECT next_scan_at FROM repositories WHERE id = $1", r.ID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("next_scan_at = %v, want %v", got, want)
	}
	// Not due yet, so the scheduler must not claim it.
	ids, err := repos.ClaimDueRepositories(ctx, time.Now().UTC(), 10, func(string, time.Time) time.Time { return want })
	if err != nil || len(ids) != 0 {
		t.Fatalf("ClaimDueRepositories = %v, %v; want none", ids, err)
	}
}

func TestCreateDuplicateURLReturnsErrDuplicate(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	first := entity.NewRepository("Eps", "https://github.com/o/eps", entity.GitProviderGitHub, "")
	if err := repos.Create(ctx, first, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	again := entity.NewRepository("Eps again", "https://github.com/o/eps", entity.GitProviderGitHub, "")
	if err := repos.Create(ctx, again, time.Now().UTC()); !errors.Is(err, repository.ErrDuplicate) {
		t.Fatalf("Create of a duplicate URL = %v, want ErrDuplicate", err)
	}
}
