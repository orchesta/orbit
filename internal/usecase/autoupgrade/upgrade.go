package autoupgrade

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/domain/repository"
	"github.com/google/uuid"
)

// PullRequestCreator defines the interface for creating pull requests on Git providers.
type PullRequestCreator interface {
	// CreateBranch creates a new branch from the default branch.
	CreateBranch(ctx context.Context, opts CreateBranchOptions) error
	// UpdateFile updates a file in the given branch.
	UpdateFile(ctx context.Context, opts UpdateFileOptions) error
	// CreatePullRequest creates a pull request from a branch to the default branch.
	CreatePullRequest(ctx context.Context, opts CreatePROptions) (*PullRequest, error)
}

type CreateBranchOptions struct {
	RepoURL    string
	AuthToken  string
	BranchName string
	BaseBranch string
}

type UpdateFileOptions struct {
	RepoURL   string
	AuthToken string
	Branch    string
	FilePath  string
	Content   []byte
	Message   string
}

type CreatePROptions struct {
	RepoURL    string
	AuthToken  string
	Title      string
	Body       string
	HeadBranch string
	BaseBranch string
}

type PullRequest struct {
	URL    string
	Number int
}

// UseCase handles automatic dependency upgrade PR creation.
type UseCase struct {
	repoRepo  repository.RepositoryRepo
	depRepo   repository.DependencyRepo
	prCreator func(entity.GitProvider) PullRequestCreator
	logger    *slog.Logger
}

// NewUseCase creates a new auto-upgrade use case.
func NewUseCase(
	repoRepo repository.RepositoryRepo,
	depRepo repository.DependencyRepo,
	prCreator func(entity.GitProvider) PullRequestCreator,
	logger *slog.Logger,
) *UseCase {
	return &UseCase{
		repoRepo:  repoRepo,
		depRepo:   depRepo,
		prCreator: prCreator,
		logger:    logger,
	}
}

// UpgradeResult contains the result of an auto-upgrade attempt.
type UpgradeResult struct {
	DependencyName string
	FromVersion    string
	ToVersion      string
	PRUrl          string
	Error          string
}

// UpgradeDependency creates a PR to upgrade a single dependency to its latest version.
func (uc *UseCase) UpgradeDependency(ctx context.Context, repoID, depID uuid.UUID) (*UpgradeResult, error) {
	// Get repo
	repo, err := uc.repoRepo.GetByID(ctx, repoID)
	if err != nil || repo == nil {
		return nil, fmt.Errorf("repository not found: %w", err)
	}

	// Get dependency
	dep, err := uc.depRepo.GetByID(ctx, depID)
	if err != nil || dep == nil {
		return nil, fmt.Errorf("dependency not found: %w", err)
	}

	if !dep.IsOutdated || dep.LatestVersion == "" {
		return &UpgradeResult{
			DependencyName: dep.Name,
			Error:          "dependency is already up to date",
		}, nil
	}

	result := &UpgradeResult{
		DependencyName: dep.Name,
		FromVersion:    dep.CurrentVersion,
		ToVersion:      dep.LatestVersion,
	}

	prCreator := uc.prCreator(repo.Provider)

	// Create branch
	branchName := fmt.Sprintf("orbit/upgrade-%s-%s-%d",
		sanitizeBranchName(dep.Name),
		dep.LatestVersion,
		time.Now().Unix(),
	)

	err = prCreator.CreateBranch(ctx, CreateBranchOptions{
		RepoURL:    repo.URL,
		AuthToken:  repo.AuthToken,
		BranchName: branchName,
		BaseBranch: repo.DefaultBranch,
	})
	if err != nil {
		result.Error = fmt.Sprintf("failed to create branch: %v", err)
		return result, nil
	}

	// Update manifest file — replace old version with new
	// Note: actual implementation would read + parse + modify the manifest
	// Here we create a placeholder commit message
	commitMsg := fmt.Sprintf("chore(deps): upgrade %s from %s to %s",
		dep.Name, dep.CurrentVersion, dep.LatestVersion,
	)

	err = prCreator.UpdateFile(ctx, UpdateFileOptions{
		RepoURL:   repo.URL,
		AuthToken: repo.AuthToken,
		Branch:    branchName,
		FilePath:  dep.ManifestFile,
		Message:   commitMsg,
	})
	if err != nil {
		result.Error = fmt.Sprintf("failed to update manifest: %v", err)
		return result, nil
	}

	// Create PR
	prBody := fmt.Sprintf(`## 🔄 Dependency Upgrade

**Package:** %s
**Ecosystem:** %s
**Current Version:** %s
**New Version:** %s
**Update Type:** %s
**Manifest File:** %s

---
*This PR was automatically created by [Orbit](https://github.com/aligoren/orbit).*`,
		dep.Name,
		dep.Ecosystem,
		dep.CurrentVersion,
		dep.LatestVersion,
		dep.UpdateType,
		"`"+dep.ManifestFile+"`",
	)

	pr, err := prCreator.CreatePullRequest(ctx, CreatePROptions{
		RepoURL:    repo.URL,
		AuthToken:  repo.AuthToken,
		Title:      fmt.Sprintf("⬆️ Upgrade %s to %s", dep.Name, dep.LatestVersion),
		Body:       prBody,
		HeadBranch: branchName,
		BaseBranch: repo.DefaultBranch,
	})
	if err != nil {
		result.Error = fmt.Sprintf("failed to create PR: %v", err)
		return result, nil
	}

	result.PRUrl = pr.URL

	uc.logger.Info("auto-upgrade PR created",
		slog.String("repo", repo.Name),
		slog.String("package", dep.Name),
		slog.String("from", dep.CurrentVersion),
		slog.String("to", dep.LatestVersion),
		slog.String("pr_url", pr.URL),
	)

	return result, nil
}

func sanitizeBranchName(name string) string {
	replacer := strings.NewReplacer("/", "-", "@", "", " ", "-")
	return replacer.Replace(strings.ToLower(name))
}
