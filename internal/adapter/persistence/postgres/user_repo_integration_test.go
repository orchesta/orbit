//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

func newAdmin(t *testing.T, email string) *entity.User {
	t.Helper()
	u, err := entity.NewUser(email, "password123", "Admin", entity.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCreateInitialAdminOnlyOnce(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repo := NewUserPostgresRepo(pool)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, email := range []string{"a@example.com", "b@example.com"} {
		wg.Add(1)
		go func(i int, email string) {
			defer wg.Done()
			errs[i] = repo.CreateInitialAdmin(ctx, newAdmin(t, email))
		}(i, email)
	}
	wg.Wait()

	ok, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, repository.ErrSetupAlreadyCompleted):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatalf("ok=%d conflicts=%d, want exactly one winner", ok, conflicts)
	}
	if n, err := repo.Count(ctx); err != nil || n != 1 {
		t.Fatalf("users = %d, %v; want 1", n, err)
	}
	if err := repo.CreateInitialAdmin(ctx, newAdmin(t, "c@example.com")); !errors.Is(err, repository.ErrSetupAlreadyCompleted) {
		t.Fatalf("third setup: %v", err)
	}
}

func TestGetByEmailIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	repo := NewUserPostgresRepo(newTestPool(t))
	if err := repo.Create(ctx, newAdmin(t, "Admin@Example.com")); err != nil {
		t.Fatal(err)
	}
	u, err := repo.GetByEmail(ctx, "admin@example.com")
	if err != nil || u == nil {
		t.Fatalf("GetByEmail = %v, %v", u, err)
	}
}

func TestCreateInitialAdminRefusedWhenUserExistsButFlagUnset(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repo := NewUserPostgresRepo(pool)

	// An older install could hold an admin while setup_completed stayed 'false'.
	if err := repo.Create(ctx, newAdmin(t, "existing@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateInitialAdmin(ctx, newAdmin(t, "intruder@example.com")); !errors.Is(err, repository.ErrSetupAlreadyCompleted) {
		t.Fatalf("CreateInitialAdmin = %v, want ErrSetupAlreadyCompleted", err)
	}
	if n, err := repo.Count(ctx); err != nil || n != 1 {
		t.Fatalf("users = %d, %v; want 1", n, err)
	}
	flag, err := NewSystemConfigPostgresRepo(pool).Get(ctx, "setup_completed")
	if err != nil || flag != "true" {
		t.Fatalf("setup_completed = %q, %v; want self-healed to 'true'", flag, err)
	}
}
