//go:build integration

package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/infrastructure/crypto"
	"github.com/google/uuid"
)

const (
	testKey  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	otherKey = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
)

func testSealer(t *testing.T, key string) *crypto.Encryptor {
	t.Helper()
	e, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAccessTokenSealedAtRest(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repo := NewAccessTokenPostgresRepo(pool, testSealer(t, testKey))

	tok, err := repo.Create(ctx, "ci", "github", nil, "ghp_supersecretvalue1234")
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := pool.QueryRow(ctx, "SELECT token FROM access_tokens WHERE id = $1", tok.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "enc:v1:") || strings.Contains(raw, "supersecret") {
		t.Fatalf("stored token %q is not sealed", raw)
	}

	got, err := repo.GetByID(ctx, tok.ID)
	if err != nil || got.Token != "ghp_supersecretvalue1234" {
		t.Fatalf("GetByID = %+v, %v", got, err)
	}
	all, err := repo.GetAll(ctx)
	if err != nil || len(all) != 1 || all[0].Masked != "****1234" {
		t.Fatalf("GetAll = %+v, %v", all, err)
	}
}

func TestRepositoryAuthTokenSealedAtRest(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repo := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))

	r := entity.NewRepository("app", "https://github.com/o/app", entity.GitProviderGitHub, "ghp_repotoken5678")
	if err := repo.Create(ctx, r, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := pool.QueryRow(ctx, "SELECT auth_token FROM repositories WHERE id = $1", r.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "enc:v1:") || strings.Contains(raw, "repotoken") {
		t.Fatalf("stored auth_token %q is not sealed", raw)
	}
	got, err := repo.GetByID(ctx, r.ID)
	if err != nil || got.AuthToken != "ghp_repotoken5678" {
		t.Fatalf("GetByID = %+v, %v", got, err)
	}

	r.AuthToken = "ghp_rotated9999"
	if err := repo.Update(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT auth_token FROM repositories WHERE id = $1", r.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("updated auth_token %q is not sealed", raw)
	}
}

func TestSealPlaintextSecretsMigratesLegacyRows(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	sealer := testSealer(t, testKey)

	tokenID, repoID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO access_tokens (id, label, provider, token, created_at) VALUES ($1, 'legacy', 'github', 'ghp_legacytoken0001', $2)", tokenID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO repositories (id, name, url, provider, auth_token) VALUES ($1, 'legacy', 'https://github.com/o/legacy', 'github', 'ghp_legacyrepo0002')", repoID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO repositories (id, name, url, provider, auth_token) VALUES ($1, 'public', 'https://github.com/o/public', 'github', '')", uuid.New()); err != nil {
		t.Fatal(err)
	}

	n, err := SealPlaintextSecrets(ctx, pool, sealer)
	if err != nil || n != 2 {
		t.Fatalf("SealPlaintextSecrets = %d, %v; want 2", n, err)
	}
	if n, err := SealPlaintextSecrets(ctx, pool, sealer); err != nil || n != 0 {
		t.Fatalf("second run = %d, %v; want 0 (idempotent)", n, err)
	}

	tok, err := NewAccessTokenPostgresRepo(pool, sealer).GetByID(ctx, tokenID)
	if err != nil || tok.Token != "ghp_legacytoken0001" {
		t.Fatalf("migrated token = %+v, %v", tok, err)
	}
	r, err := NewRepositoryPostgresRepo(pool, sealer).GetByID(ctx, repoID)
	if err != nil || r.AuthToken != "ghp_legacyrepo0002" {
		t.Fatalf("migrated repo = %+v, %v", r, err)
	}
	var empty string
	if err := pool.QueryRow(ctx, "SELECT auth_token FROM repositories WHERE name = 'public'").Scan(&empty); err != nil || empty != "" {
		t.Fatalf("empty auth_token must stay empty, got %q, %v", empty, err)
	}
}

func TestReadWithWrongKeyFails(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	tok, err := NewAccessTokenPostgresRepo(pool, testSealer(t, testKey)).Create(ctx, "ci", "github", nil, "ghp_supersecretvalue1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAccessTokenPostgresRepo(pool, testSealer(t, otherKey)).GetByID(ctx, tok.ID); err == nil {
		t.Fatal("reading with the wrong key must fail instead of returning garbage")
	}
}

func TestSealPlaintextSecretsRejectsWrongKey(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	if _, err := NewAccessTokenPostgresRepo(pool, testSealer(t, testKey)).Create(ctx, "ci", "github", nil, "ghp_supersecretvalue1234"); err != nil {
		t.Fatal(err)
	}

	n, err := SealPlaintextSecrets(ctx, pool, testSealer(t, otherKey))
	if err == nil || !strings.Contains(err.Error(), "ORBIT_CRYPTO_ENCRYPTION_KEY") || !strings.Contains(err.Error(), "access_tokens.token") {
		t.Fatalf("SealPlaintextSecrets with another key = %d, %v; want a key mismatch error", n, err)
	}
	if n, err := SealPlaintextSecrets(ctx, pool, testSealer(t, testKey)); err != nil || n != 0 {
		t.Fatalf("SealPlaintextSecrets with the original key = %d, %v; want 0, nil", n, err)
	}
}
