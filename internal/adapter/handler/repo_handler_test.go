package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/usecase/repo"
)

type stubRepoRepo struct {
	repository.RepositoryRepo
	createErr error
}

func (s stubRepoRepo) Create(context.Context, *entity.Repository, time.Time) error {
	return s.createErr
}

func TestCreateRepositoryRejectsForeignHostWith400(t *testing.T) {
	r := chi.NewRouter()
	NewRepoHandler(repo.NewUseCase(stubRepoRepo{}, nil), nil, nil, nil, nil, nil).RegisterRoutes(r)

	body := `{"name":"x","url":"https://evil.example/o/r","provider":"github"}`
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/repositories/", strings.NewReader(body)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "host must be github.com") {
		t.Fatalf("body should explain the rejection: %s", rec.Body)
	}
}

func TestBulkImportRejectsTooManyRepositories(t *testing.T) {
	r := chi.NewRouter()
	NewRepoHandler(repo.NewUseCase(stubRepoRepo{}, nil), nil, nil, nil, nil, nil).RegisterRoutes(r)

	var b strings.Builder
	b.WriteString(`{"token_id":"00000000-0000-0000-0000-000000000000","provider":"github","repositories":[`)
	for i := 0; i < 501; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name":"r","url":"https://github.com/o/r"}`)
	}
	b.WriteString(`]}`)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/repositories/import", strings.NewReader(b.String())))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at most 500") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestCreateRepositoryRejectsInvalidScheduleWith400(t *testing.T) {
	r := chi.NewRouter()
	NewRepoHandler(repo.NewUseCase(stubRepoRepo{}, nil), nil, nil, nil, nil, nil).RegisterRoutes(r)

	body := `{"name":"x","url":"https://github.com/o/r","provider":"github","schedule":"*/5 * * * *"}`
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/repositories/", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at least 15m") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestCreateRepositoryDuplicateReturns409(t *testing.T) {
	r := chi.NewRouter()
	NewRepoHandler(repo.NewUseCase(stubRepoRepo{createErr: repository.ErrDuplicate}, nil), nil, nil, nil, nil, nil).RegisterRoutes(r)

	body := `{"name":"x","url":"https://github.com/o/r","provider":"github"}`
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/repositories/", strings.NewReader(body)))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "repository already exists") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}
