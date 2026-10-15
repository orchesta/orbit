//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/domain/repository"
	"github.com/google/uuid"
)

func newTestHost(t *testing.T, name, baseURL string) *entity.GitHost {
	t.Helper()
	h, err := entity.NewGitHost(entity.GitProviderAzureDevOps, name, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestGitHostCreateGetList(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	hosts := NewGitHostPostgresRepo(pool)

	b := newTestHost(t, "Beta", "https://dev.azure.com/beta")
	a := newTestHost(t, "Alpha", "https://dev.azure.com/alpha")
	for _, h := range []*entity.GitHost{b, a} {
		if err := hosts.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
	}

	got, err := hosts.GetByID(ctx, a.ID)
	if err != nil || got == nil {
		t.Fatalf("GetByID = %v, %v", got, err)
	}
	if got.Name != "Alpha" || got.BaseURL != a.BaseURL || got.Kind != entity.GitProviderAzureDevOps {
		t.Fatalf("GetByID = %+v", got)
	}
	if missing, err := hosts.GetByID(ctx, uuid.New()); err != nil || missing != nil {
		t.Fatalf("GetByID(missing) = %v, %v; want nil, nil", missing, err)
	}

	list, err := hosts.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "Alpha" || list[1].Name != "Beta" {
		t.Fatalf("List = %+v", list)
	}
}

func TestGitHostDuplicateBaseURL(t *testing.T) {
	ctx := context.Background()
	hosts := NewGitHostPostgresRepo(newTestPool(t))
	if err := hosts.Create(ctx, newTestHost(t, "One", "https://dev.azure.com/org")); err != nil {
		t.Fatal(err)
	}
	if err := hosts.Create(ctx, newTestHost(t, "Two", "https://dev.azure.com/org")); !errors.Is(err, repository.ErrDuplicate) {
		t.Fatalf("second Create = %v, want ErrDuplicate", err)
	}
}

// Azure organization and collection names are case-insensitive, so base URLs
// that differ only in path case name the same connection.
func TestGitHostDuplicateBaseURLIgnoresPathCase(t *testing.T) {
	ctx := context.Background()
	hosts := NewGitHostPostgresRepo(newTestPool(t))
	if err := hosts.Create(ctx, newTestHost(t, "One", "https://tfs.local/tfs/Col")); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"https://tfs.local/tfs/col", "https://TFS.local/TFS/COL"} {
		if err := hosts.Create(ctx, newTestHost(t, "Two", u)); !errors.Is(err, repository.ErrDuplicate) {
			t.Fatalf("Create(%s) = %v, want ErrDuplicate", u, err)
		}
	}
	if err := hosts.Create(ctx, newTestHost(t, "Other", "https://tfs.local/tfs/Col2")); err != nil {
		t.Fatalf("a different collection must be accepted: %v", err)
	}
}

func TestGitHostDeleteReferencedByRepositoryIsInUse(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	hosts := NewGitHostPostgresRepo(pool)
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	h := newTestHost(t, "Corp", "https://dev.azure.com/corp")
	if err := hosts.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	r := entity.NewRepository("svc", "https://dev.azure.com/corp/p/_git/svc", entity.GitProviderAzureDevOps, "")
	r.GitHostID = &h.ID
	if err := repos.Create(ctx, r, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	if err := hosts.Delete(ctx, h.ID); !errors.Is(err, repository.ErrInUse) {
		t.Fatalf("Delete = %v, want ErrInUse", err)
	}
	if got, _ := hosts.GetByID(ctx, h.ID); got == nil {
		t.Fatal("host was deleted despite being in use")
	}

	if err := repos.Delete(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := hosts.Delete(ctx, h.ID); err != nil {
		t.Fatalf("Delete after repo removal = %v", err)
	}
}

func TestGitHostDeleteCascadesTokens(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	hosts := NewGitHostPostgresRepo(pool)
	tokens := NewAccessTokenPostgresRepo(pool, testSealer(t, testKey))
	h := newTestHost(t, "Corp", "https://dev.azure.com/corp")
	if err := hosts.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.Create(ctx, "azure", "azuredevops", &h.ID, "pat_supersecretvalue1234")
	if err != nil {
		t.Fatal(err)
	}
	other, err := tokens.Create(ctx, "gh", "github", nil, "ghp_supersecretvalue1234")
	if err != nil {
		t.Fatal(err)
	}

	if err := hosts.Delete(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM access_tokens WHERE id = $1", tok.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("host token count = %d, err %v; want 0", n, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM access_tokens WHERE id = $1", other.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("unrelated token count = %d, err %v; want 1", n, err)
	}
}

func TestGitHostIDRoundTripsOnTokenAndRepository(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	hosts := NewGitHostPostgresRepo(pool)
	tokens := NewAccessTokenPostgresRepo(pool, testSealer(t, testKey))
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	h := newTestHost(t, "Corp", "https://dev.azure.com/corp")
	if err := hosts.Create(ctx, h); err != nil {
		t.Fatal(err)
	}

	tok, err := tokens.Create(ctx, "azure", "azuredevops", &h.ID, "pat_supersecretvalue1234")
	if err != nil {
		t.Fatal(err)
	}
	if tok.GitHostID == nil || *tok.GitHostID != h.ID {
		t.Fatalf("created token GitHostID = %v", tok.GitHostID)
	}
	byID, err := tokens.GetByID(ctx, tok.ID)
	if err != nil || byID.GitHostID == nil || *byID.GitHostID != h.ID {
		t.Fatalf("GetByID token = %+v, %v", byID, err)
	}
	all, err := tokens.GetAll(ctx)
	if err != nil || len(all) != 1 || all[0].GitHostID == nil || *all[0].GitHostID != h.ID {
		t.Fatalf("GetAll tokens = %+v, %v", all, err)
	}

	r := entity.NewRepository("svc", "https://dev.azure.com/corp/p/_git/svc", entity.GitProviderAzureDevOps, "")
	r.GitHostID = &h.ID
	if err := repos.Create(ctx, r, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, err := repos.GetByID(ctx, r.ID)
	if err != nil || got == nil || got.GitHostID == nil || *got.GitHostID != h.ID {
		t.Fatalf("GetByID repo = %+v, %v", got, err)
	}
	list, err := repos.GetAll(ctx)
	if err != nil || len(list) != 1 || list[0].GitHostID == nil || *list[0].GitHostID != h.ID {
		t.Fatalf("GetAll repos = %+v, %v", list, err)
	}
	active, err := repos.GetActive(ctx)
	if err != nil || len(active) != 1 || active[0].GitHostID == nil {
		t.Fatalf("GetActive repos = %+v, %v", active, err)
	}

	// Update carries the column, including clearing it.
	got.GitHostID = nil
	if err := repos.Update(ctx, got, nil); err != nil {
		t.Fatal(err)
	}
	cleared, err := repos.GetByID(ctx, r.ID)
	if err != nil || cleared.GitHostID != nil {
		t.Fatalf("after clearing: %+v, %v", cleared, err)
	}
	cleared.GitHostID = &h.ID
	if err := repos.Update(ctx, cleared, nil); err != nil {
		t.Fatal(err)
	}
	again, err := repos.GetByID(ctx, r.ID)
	if err != nil || again.GitHostID == nil || *again.GitHostID != h.ID {
		t.Fatalf("after setting: %+v, %v", again, err)
	}

	// A repository without a host reads back nil.
	plain := newQueueRepo(t, ctx, pool, "Plain")
	p, err := repos.GetByID(ctx, plain)
	if err != nil || p.GitHostID != nil {
		t.Fatalf("plain repo GitHostID = %v, %v", p.GitHostID, err)
	}
}

// gitHostsMigration is the version of 000006_git_hosts. The down/up test
// migrates to absolute versions so later migrations do not shift it.
const gitHostsMigration uint = 6

func TestGitHostsMigrationDownUp(t *testing.T) {
	ctx := context.Background()
	pool := newTestPoolAtVersion(t, gitHostsMigration-1)
	m := newTestMigrator(t, pool.Config().ConnString())

	assertGitHostsSchema := func(stage string, present bool) {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE column_name = 'git_host_id'").Scan(&n); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		var table, index bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass('git_hosts') IS NOT NULL, to_regclass('git_hosts_base_url_lower_key') IS NOT NULL").Scan(&table, &index); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		want := 0
		if present {
			want = 2
		}
		if n != want || table != present || index != present {
			t.Fatalf("%s: git_host_id columns = %d (want %d), git_hosts table present = %v, base_url index present = %v (want %v)", stage, n, want, table, index, present)
		}
	}

	assertGitHostsSchema("before", false)
	if err := m.Migrate(gitHostsMigration); err != nil {
		t.Fatalf("up to %d: %v", gitHostsMigration, err)
	}
	assertGitHostsSchema("after up", true)
	if err := m.Migrate(gitHostsMigration - 1); err != nil {
		t.Fatalf("down to %d: %v", gitHostsMigration-1, err)
	}
	assertGitHostsSchema("after down", false)
}
