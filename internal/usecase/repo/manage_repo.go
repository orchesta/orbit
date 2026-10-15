package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/usecase/schedule"
)

// ErrGitHostNotFound is returned when a repository names a connection that
// does not exist.
var ErrGitHostNotFound = errors.New("connection not found")

// UseCase handles repository management operations.
type UseCase struct {
	repoRepo repository.RepositoryRepo
	gitHosts repository.GitHostRepo
}

// NewUseCase creates a new repository management use case.
func NewUseCase(repoRepo repository.RepositoryRepo, gitHosts repository.GitHostRepo) *UseCase {
	return &UseCase{repoRepo: repoRepo, gitHosts: gitHosts}
}

// CreateInput holds the input for creating a repository.
type CreateInput struct {
	Name          string
	URL           string
	Provider      entity.GitProvider
	DefaultBranch string
	Schedule      string
	AuthToken     string
	// GitHostID names the connection of an Azure DevOps repository; other
	// providers must leave it nil.
	GitHostID *uuid.UUID
}

// ExistingURLs reports which of urls are already stored (normalized).
func (uc *UseCase) ExistingURLs(ctx context.Context, urls []string) (map[string]bool, error) {
	return uc.repoRepo.ExistingURLs(ctx, urls)
}

// validateLocation checks a repository's clone location and returns the URL
// to store: Azure DevOps repositories must name an existing connection and
// sit under its base URL (their URL is canonicalized, see
// entity.CanonicalHostedRepositoryURL); other providers must not name a
// connection and keep their URL as given.
func (uc *UseCase) validateLocation(ctx context.Context, provider entity.GitProvider, rawURL string, gitHostID *uuid.UUID) (string, error) {
	if provider != entity.GitProviderAzureDevOps {
		if gitHostID != nil {
			return "", fmt.Errorf("%w: only azuredevops repositories use a connection", entity.ErrInvalidRepositoryURL)
		}
		return rawURL, entity.ValidateRepositoryURL(provider, rawURL)
	}
	if gitHostID == nil {
		return "", fmt.Errorf("%w: azure devops repositories need a connection", entity.ErrInvalidRepositoryURL)
	}
	host, err := uc.gitHosts.GetByID(ctx, *gitHostID)
	if err != nil {
		return "", fmt.Errorf("failed to get connection: %w", err)
	}
	if host == nil {
		return "", ErrGitHostNotFound
	}
	if host.Kind != provider {
		return "", fmt.Errorf("%w: connection is not a %s connection", entity.ErrInvalidRepositoryURL, provider)
	}
	return entity.CanonicalHostedRepositoryURL(host, rawURL)
}

// Create registers a new repository for scanning.
func (uc *UseCase) Create(ctx context.Context, input CreateInput) (*entity.Repository, error) {
	canonical, err := uc.validateLocation(ctx, input.Provider, input.URL, input.GitHostID)
	if err != nil {
		return nil, err
	}
	input.URL = canonical
	if input.DefaultBranch == "" {
		input.DefaultBranch = "main"
	}
	if input.Schedule == "" {
		input.Schedule = "0 */6 * * *"
	}
	if err := schedule.Validate(input.Schedule); err != nil {
		return nil, err
	}

	repo := entity.NewRepository(input.Name, input.URL, input.Provider, input.AuthToken)
	repo.DefaultBranch = input.DefaultBranch
	repo.Schedule = input.Schedule
	repo.GitHostID = input.GitHostID

	// Due immediately: the scheduler scans the repository on its next tick.
	// A scan requested right after creation postpones this (see
	// scan.UseCase.RequestScan), so the two do not double up.
	if err := uc.repoRepo.Create(ctx, repo, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	return repo, nil
}

// GetByID retrieves a repository by its ID.
func (uc *UseCase) GetByID(ctx context.Context, id uuid.UUID) (*entity.Repository, error) {
	repo, err := uc.repoRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	return repo, nil
}

// GetAll retrieves all repositories.
func (uc *UseCase) GetAll(ctx context.Context) ([]*entity.Repository, error) {
	repos, err := uc.repoRepo.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get repositories: %w", err)
	}
	return repos, nil
}

// UpdateInput holds the input for updating a repository.
type UpdateInput struct {
	Name          *string
	URL           *string
	Provider      *entity.GitProvider
	DefaultBranch *string
	Schedule      *string
	AuthToken     *string
	IsActive      *bool
	// GitHostID moves the repository to another connection; nil keeps it.
	GitHostID *uuid.UUID
}

// Update modifies an existing repository.
func (uc *UseCase) Update(ctx context.Context, id uuid.UUID, input UpdateInput) (*entity.Repository, error) {
	repo, err := uc.repoRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	if repo == nil {
		return nil, fmt.Errorf("repository not found")
	}
	reactivated := input.IsActive != nil && *input.IsActive && !repo.IsActive
	oldProvider, oldGitHostID := repo.Provider, repo.GitHostID

	if input.Name != nil {
		repo.Name = *input.Name
	}
	locationChanged := false
	if input.URL != nil {
		repo.URL = *input.URL
		locationChanged = true
	}
	if input.Provider != nil {
		repo.Provider = *input.Provider
		locationChanged = true
	}
	if input.GitHostID != nil {
		hostID := *input.GitHostID
		repo.GitHostID = &hostID
		locationChanged = true
	}
	if input.DefaultBranch != nil {
		repo.DefaultBranch = *input.DefaultBranch
	}
	scheduleChanged := false
	if input.Schedule != nil {
		if err := schedule.Validate(*input.Schedule); err != nil {
			return nil, err
		}
		repo.Schedule = *input.Schedule
		scheduleChanged = true
	}
	if input.AuthToken != nil {
		repo.AuthToken = *input.AuthToken
	}
	if input.IsActive != nil {
		repo.IsActive = *input.IsActive
	}
	// Only re-validate when the clone location changes, so legacy rows can
	// still be renamed or deactivated.
	if locationChanged {
		// Only Azure DevOps repositories have a connection, so moving one to
		// another provider drops it unless the request names one (which
		// validateLocation then rejects).
		if repo.Provider != entity.GitProviderAzureDevOps && input.GitHostID == nil {
			repo.GitHostID = nil
		}
		canonical, err := uc.validateLocation(ctx, repo.Provider, repo.URL, repo.GitHostID)
		if err != nil {
			return nil, err
		}
		repo.URL = canonical
		// A stored token belongs to the host it was issued for: moving the
		// repository to another provider or connection drops it unless the
		// request sends a new one, so a PAT never follows a repository to a
		// new host. Scans then clone anonymously and private repositories
		// fail visibly until a token is entered again.
		if input.AuthToken == nil && (repo.Provider != oldProvider || !sameGitHost(repo.GitHostID, oldGitHostID)) {
			repo.AuthToken = ""
		}
	}
	// A new schedule or a reactivated repository takes effect right away
	// instead of waiting for the previously computed run. Compute it before
	// saving so an unusable schedule rejects the whole update, and save it in
	// the same call so the two cannot diverge.
	var nextScanAt *time.Time
	if scheduleChanged || reactivated {
		next, err := schedule.Next(repo.Schedule, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if next.IsZero() {
			return nil, fmt.Errorf("%w: expression never runs", schedule.ErrInvalidSchedule)
		}
		nextScanAt = &next
	}
	repo.UpdatedAt = time.Now().UTC()

	if err := uc.repoRepo.Update(ctx, repo, nextScanAt); err != nil {
		return nil, fmt.Errorf("failed to update repository: %w", err)
	}

	return repo, nil
}

// sameGitHost reports whether a and b name the same connection (or both none).
func sameGitHost(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Delete removes a repository.
func (uc *UseCase) Delete(ctx context.Context, id uuid.UUID) error {
	if err := uc.repoRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete repository: %w", err)
	}
	return nil
}
