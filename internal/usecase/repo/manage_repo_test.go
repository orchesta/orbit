package repo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/usecase/schedule"
)

// fakeRepoRepo implements only the methods these tests call; the embedded
// interface makes any other call panic, so a separate SetNextScanAt call from
// Update would fail the test.
type fakeRepoRepo struct {
	repository.RepositoryRepo
	stored   *entity.Repository
	created  int
	updated  int
	nextScan map[uuid.UUID]time.Time
	// updateNext records the next-scan time each Update call carried (nil when none).
	updateNext []*time.Time
	// createNext is the next-scan time the Create call carried.
	createNext time.Time
}

func (f *fakeRepoRepo) Create(_ context.Context, r *entity.Repository, nextScanAt time.Time) error {
	f.created++
	f.createNext = nextScanAt
	f.stored = r
	return nil
}

func (f *fakeRepoRepo) GetByID(_ context.Context, _ uuid.UUID) (*entity.Repository, error) {
	return f.stored, nil
}

func (f *fakeRepoRepo) Update(_ context.Context, r *entity.Repository, nextScanAt *time.Time) error {
	f.updated++
	f.stored = r
	f.updateNext = append(f.updateNext, nextScanAt)
	if nextScanAt != nil {
		if f.nextScan == nil {
			f.nextScan = map[uuid.UUID]time.Time{}
		}
		f.nextScan[r.ID] = *nextScanAt
	}
	return nil
}

func TestCreateRejectsForeignHost(t *testing.T) {
	store := &fakeRepoRepo{}
	_, err := NewUseCase(store, nil).Create(context.Background(), CreateInput{
		Name: "x", URL: "https://evil.example/o/r", Provider: entity.GitProviderGitHub, AuthToken: "tok",
	})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.created != 0 {
		t.Fatal("repository must not be persisted")
	}
}

func TestCreateAcceptsProviderURL(t *testing.T) {
	store := &fakeRepoRepo{}
	if _, err := NewUseCase(store, nil).Create(context.Background(), CreateInput{
		Name: "express", URL: "https://github.com/expressjs/express", Provider: entity.GitProviderGitHub,
	}); err != nil {
		t.Fatal(err)
	}
	if store.created != 1 {
		t.Fatal("repository should be persisted")
	}
}

func TestUpdateRejectsURLChangeToForeignHost(t *testing.T) {
	store := &fakeRepoRepo{stored: entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "tok")}
	evil := "https://evil.example/o/r"
	_, err := NewUseCase(store, nil).Update(context.Background(), store.stored.ID, UpdateInput{URL: &evil})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.updated != 0 {
		t.Fatal("repository must not be updated")
	}
}

func TestUpdateKeepsLegacyURLWhenNotChanged(t *testing.T) {
	store := &fakeRepoRepo{stored: entity.NewRepository("r", "http://legacy.example/o/r", entity.GitProviderGitHub, "")}
	inactive := false
	if _, err := NewUseCase(store, nil).Update(context.Background(), store.stored.ID, UpdateInput{IsActive: &inactive}); err != nil {
		t.Fatalf("toggling is_active on a legacy repo must still work: %v", err)
	}
}

func TestCreateRejectsInvalidSchedule(t *testing.T) {
	store := &fakeRepoRepo{}
	for _, expr := range []string{"every 6h", "*/5 * * * *"} {
		_, err := NewUseCase(store, nil).Create(context.Background(), CreateInput{
			Name: "x", URL: "https://github.com/o/r", Provider: entity.GitProviderGitHub, Schedule: expr,
		})
		if !errors.Is(err, schedule.ErrInvalidSchedule) {
			t.Fatalf("%q: want ErrInvalidSchedule, got %v", expr, err)
		}
	}
	if store.created != 0 {
		t.Fatal("repository with an invalid schedule must not be persisted")
	}
}

func TestUpdateRecomputesNextScanAt(t *testing.T) {
	r := entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "")
	store := &fakeRepoRepo{stored: r}
	daily := "0 3 * * *"
	before := time.Now().UTC()
	if _, err := NewUseCase(store, nil).Update(context.Background(), r.ID, UpdateInput{Schedule: &daily}); err != nil {
		t.Fatal(err)
	}
	next, ok := store.nextScan[r.ID]
	if !ok || !next.After(before) || next.Hour() != 3 || next.Minute() != 0 {
		t.Fatalf("next scan = %v (set=%v), want the next 03:00 after now", next, ok)
	}
}

func TestUpdateReactivationSchedulesScan(t *testing.T) {
	r := entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "")
	r.IsActive = false
	store := &fakeRepoRepo{stored: r}
	active := true
	if _, err := NewUseCase(store, nil).Update(context.Background(), r.ID, UpdateInput{IsActive: &active}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.nextScan[r.ID]; !ok {
		t.Fatal("reactivating a repository must schedule its next scan")
	}
}

func TestUpdateRejectsInvalidSchedule(t *testing.T) {
	r := entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "")
	store := &fakeRepoRepo{stored: r}
	bad := "* * * * *"
	if _, err := NewUseCase(store, nil).Update(context.Background(), r.ID, UpdateInput{Schedule: &bad}); !errors.Is(err, schedule.ErrInvalidSchedule) {
		t.Fatalf("want ErrInvalidSchedule, got %v", err)
	}
	if store.updated != 0 {
		t.Fatal("repository must not be updated")
	}
}

func TestUpdateReactivationWithUnparseableScheduleIsRejected(t *testing.T) {
	r := entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "")
	r.IsActive = false
	r.Schedule = "every 6h"
	store := &fakeRepoRepo{stored: r}
	active := true
	_, err := NewUseCase(store, nil).Update(context.Background(), r.ID, UpdateInput{IsActive: &active})
	if !errors.Is(err, schedule.ErrInvalidSchedule) {
		t.Fatalf("want ErrInvalidSchedule, got %v", err)
	}
	if store.updated != 0 {
		t.Fatal("repository must not be updated")
	}
	if _, ok := store.nextScan[r.ID]; ok {
		t.Fatal("next scan must not be set")
	}
}

func TestUpdateStoresScheduleAndNextScanInOneCall(t *testing.T) {
	r := entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "")
	store := &fakeRepoRepo{stored: r}
	daily := "0 3 * * *"
	if _, err := NewUseCase(store, nil).Update(context.Background(), r.ID, UpdateInput{Schedule: &daily}); err != nil {
		t.Fatal(err)
	}
	if len(store.updateNext) != 1 || store.updateNext[0] == nil {
		t.Fatalf("Update calls = %v, want exactly one carrying next_scan_at", store.updateNext)
	}
	if got := *store.updateNext[0]; got.Hour() != 3 || got.Minute() != 0 {
		t.Fatalf("next_scan_at = %v, want the next 03:00", got)
	}
}

func TestUpdateWithoutScheduleChangeKeepsNextScan(t *testing.T) {
	r := entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "")
	store := &fakeRepoRepo{stored: r}
	name := "renamed"
	if _, err := NewUseCase(store, nil).Update(context.Background(), r.ID, UpdateInput{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if len(store.updateNext) != 1 || store.updateNext[0] != nil {
		t.Fatalf("Update calls = %v, want one leaving next_scan_at unchanged", store.updateNext)
	}
}

func TestCreateIsDueImmediately(t *testing.T) {
	store := &fakeRepoRepo{}
	before := time.Now().UTC()
	if _, err := NewUseCase(store, nil).Create(context.Background(), CreateInput{
		Name: "x", URL: "https://github.com/o/r", Provider: entity.GitProviderGitHub, Schedule: "0 3 * * *",
	}); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	if store.createNext.Before(before) || store.createNext.After(after) {
		t.Fatalf("next scan = %v, want now (between %v and %v) so the scheduler picks the repository up", store.createNext, before, after)
	}
}

// fakeGitHosts serves connections from a map; other GitHostRepo calls panic.
type fakeGitHosts struct {
	repository.GitHostRepo
	hosts map[uuid.UUID]*entity.GitHost
}

func (f fakeGitHosts) GetByID(_ context.Context, id uuid.UUID) (*entity.GitHost, error) {
	return f.hosts[id], nil
}

func mustGitHost(t *testing.T, name, baseURL string) *entity.GitHost {
	t.Helper()
	h, err := entity.NewGitHost(entity.GitProviderAzureDevOps, name, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func newHosts(hosts ...*entity.GitHost) fakeGitHosts {
	m := map[uuid.UUID]*entity.GitHost{}
	for _, h := range hosts {
		m[h.ID] = h
	}
	return fakeGitHosts{hosts: m}
}

const azureRepoURL = "https://dev.azure.com/acme/Proj/_git/Repo"

func TestCreateAzureRepositoryNeedsAConnection(t *testing.T) {
	store := &fakeRepoRepo{}
	_, err := NewUseCase(store, newHosts()).Create(context.Background(), CreateInput{
		Name: "r", URL: azureRepoURL, Provider: entity.GitProviderAzureDevOps,
	})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.created != 0 {
		t.Fatal("repository must not be persisted")
	}
}

func TestCreateGitHubRepositoryRejectsAConnection(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{}
	_, err := NewUseCase(store, newHosts(host)).Create(context.Background(), CreateInput{
		Name: "r", URL: "https://github.com/o/r", Provider: entity.GitProviderGitHub, GitHostID: &host.ID,
	})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.created != 0 {
		t.Fatal("repository must not be persisted")
	}
}

func TestCreateAzureRepositoryWithUnknownConnection(t *testing.T) {
	store := &fakeRepoRepo{}
	missing := uuid.New()
	_, err := NewUseCase(store, newHosts()).Create(context.Background(), CreateInput{
		Name: "r", URL: azureRepoURL, Provider: entity.GitProviderAzureDevOps, GitHostID: &missing,
	})
	if !errors.Is(err, ErrGitHostNotFound) {
		t.Fatalf("want ErrGitHostNotFound, got %v", err)
	}
	if store.created != 0 {
		t.Fatal("repository must not be persisted")
	}
}

func TestCreateAzureRepositoryOnAnotherHostIsRejected(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{}
	_, err := NewUseCase(store, newHosts(host)).Create(context.Background(), CreateInput{
		Name: "r", URL: "https://evil.example/acme/Proj/_git/Repo", Provider: entity.GitProviderAzureDevOps, GitHostID: &host.ID,
	})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.created != 0 {
		t.Fatal("repository must not be persisted")
	}
}

func TestCreateAzureRepositoryStoresItsConnection(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{}
	got, err := NewUseCase(store, newHosts(host)).Create(context.Background(), CreateInput{
		Name: "r", URL: azureRepoURL, Provider: entity.GitProviderAzureDevOps, GitHostID: &host.ID, AuthToken: "pat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.created != 1 || got.GitHostID == nil || *got.GitHostID != host.ID {
		t.Fatalf("created=%d git_host_id=%v, want one repository linked to %s", store.created, got.GitHostID, host.ID)
	}
}

func azureRepo(host *entity.GitHost) *entity.Repository {
	r := entity.NewRepository("r", azureRepoURL, entity.GitProviderAzureDevOps, "pat")
	id := host.ID
	r.GitHostID = &id
	return r
}

func TestUpdateAzureRepositoryURLToAnotherHostIsRejected(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{stored: azureRepo(host)}
	moved := "https://tfs.example.com/tfs/Col/Proj/_git/Repo"
	_, err := NewUseCase(store, newHosts(host)).Update(context.Background(), store.stored.ID, UpdateInput{URL: &moved})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.updated != 0 {
		t.Fatal("repository must not be updated")
	}
}

func TestUpdateAzureRepositoryConnectionIsRevalidated(t *testing.T) {
	acme := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	tfs := mustGitHost(t, "tfs", "https://tfs.example.com/tfs/Col")
	store := &fakeRepoRepo{stored: azureRepo(acme)}
	// The URL stays on dev.azure.com, so moving it to the TFS connection must fail.
	_, err := NewUseCase(store, newHosts(acme, tfs)).Update(context.Background(), store.stored.ID, UpdateInput{GitHostID: &tfs.ID})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.updated != 0 {
		t.Fatal("repository must not be updated")
	}
}

func TestUpdateAzureRepositoryURLOnItsConnection(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{stored: azureRepo(host)}
	renamed := "https://dev.azure.com/acme/Proj/_git/Renamed"
	if _, err := NewUseCase(store, newHosts(host)).Update(context.Background(), store.stored.ID, UpdateInput{URL: &renamed}); err != nil {
		t.Fatal(err)
	}
	if store.stored.URL != renamed || store.stored.GitHostID == nil || *store.stored.GitHostID != host.ID {
		t.Fatalf("stored = %s on %v, want %s on %s", store.stored.URL, store.stored.GitHostID, renamed, host.ID)
	}
}

func TestUpdateFromAzureToGitHubDropsTheConnection(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{stored: azureRepo(host)}
	gh := entity.GitProviderGitHub
	u := "https://github.com/o/r"
	if _, err := NewUseCase(store, newHosts(host)).Update(context.Background(), store.stored.ID, UpdateInput{Provider: &gh, URL: &u}); err != nil {
		t.Fatal(err)
	}
	if store.stored.GitHostID != nil {
		t.Fatalf("git_host_id = %v, want none for a GitHub repository", store.stored.GitHostID)
	}
	// The Azure PAT must not follow the repository to github.com.
	if store.stored.AuthToken != "" {
		t.Fatalf("auth token = %q, want it cleared when the provider changes", store.stored.AuthToken)
	}
}

func TestUpdateToAnotherConnectionClearsTheToken(t *testing.T) {
	acme := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	other := mustGitHost(t, "other", "https://dev.azure.com/other")
	store := &fakeRepoRepo{stored: azureRepo(acme)}
	u := "https://dev.azure.com/other/Proj/_git/Repo"
	if _, err := NewUseCase(store, newHosts(acme, other)).Update(context.Background(), store.stored.ID, UpdateInput{GitHostID: &other.ID, URL: &u}); err != nil {
		t.Fatal(err)
	}
	if store.stored.GitHostID == nil || *store.stored.GitHostID != other.ID {
		t.Fatalf("git_host_id = %v, want %s", store.stored.GitHostID, other.ID)
	}
	if store.stored.AuthToken != "" {
		t.Fatalf("auth token = %q, want it cleared when the connection changes", store.stored.AuthToken)
	}
}

func TestUpdateFromGitHubToAzureClearsTheToken(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{stored: entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "ghp_secret")}
	az := entity.GitProviderAzureDevOps
	u := azureRepoURL
	if _, err := NewUseCase(store, newHosts(host)).Update(context.Background(), store.stored.ID, UpdateInput{Provider: &az, URL: &u, GitHostID: &host.ID}); err != nil {
		t.Fatal(err)
	}
	if store.stored.AuthToken != "" {
		t.Fatalf("auth token = %q, want it cleared when the provider changes", store.stored.AuthToken)
	}
}

func TestUpdateOnTheSameConnectionKeepsTheToken(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{stored: azureRepo(host)}
	az := entity.GitProviderAzureDevOps
	renamed := "https://dev.azure.com/acme/Proj/_git/Renamed"
	name := "renamed"
	// Restating the same provider and connection is not a move.
	if _, err := NewUseCase(store, newHosts(host)).Update(context.Background(), store.stored.ID, UpdateInput{
		Name: &name, URL: &renamed, Provider: &az, GitHostID: &host.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if store.stored.AuthToken != "pat" {
		t.Fatalf("auth token = %q, want it kept on the same connection", store.stored.AuthToken)
	}
}

func TestUpdateMoveWithANewTokenKeepsTheNewToken(t *testing.T) {
	acme := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	other := mustGitHost(t, "other", "https://dev.azure.com/other")
	store := &fakeRepoRepo{stored: azureRepo(acme)}
	u := "https://dev.azure.com/other/Proj/_git/Repo"
	tok := "new-pat"
	if _, err := NewUseCase(store, newHosts(acme, other)).Update(context.Background(), store.stored.ID, UpdateInput{
		GitHostID: &other.ID, URL: &u, AuthToken: &tok,
	}); err != nil {
		t.Fatal(err)
	}
	if store.stored.AuthToken != "new-pat" {
		t.Fatalf("auth token = %q, want the token sent with the move", store.stored.AuthToken)
	}
}

func TestUpdateGitHubRepositoryRejectsAConnection(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{stored: entity.NewRepository("r", "https://github.com/o/r", entity.GitProviderGitHub, "")}
	_, err := NewUseCase(store, newHosts(host)).Update(context.Background(), store.stored.ID, UpdateInput{GitHostID: &host.ID})
	if !errors.Is(err, entity.ErrInvalidRepositoryURL) {
		t.Fatalf("want ErrInvalidRepositoryURL, got %v", err)
	}
	if store.updated != 0 {
		t.Fatal("repository must not be updated")
	}
}

// An Azure DevOps Server with ":443" in its public URL reports repository URLs
// with it; they are stored without it so they match the connection's scope.
func TestCreateAzureRepositoryStoresTheURLWithoutDefaultPort(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{}
	got, err := NewUseCase(store, newHosts(host)).Create(context.Background(), CreateInput{
		Name: "r", URL: "https://dev.azure.com:443/acme/Proj/_git/Repo", Provider: entity.GitProviderAzureDevOps, GitHostID: &host.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != azureRepoURL || store.stored.URL != azureRepoURL {
		t.Fatalf("stored url = %q, want %q", store.stored.URL, azureRepoURL)
	}
}

func TestUpdateAzureRepositoryStoresTheURLWithoutDefaultPort(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	store := &fakeRepoRepo{stored: azureRepo(host)}
	u := "https://dev.azure.com:443/acme/Proj/_git/Renamed"
	if _, err := NewUseCase(store, newHosts(host)).Update(context.Background(), store.stored.ID, UpdateInput{URL: &u}); err != nil {
		t.Fatal(err)
	}
	if want := "https://dev.azure.com/acme/Proj/_git/Renamed"; store.stored.URL != want {
		t.Fatalf("stored url = %q, want %q", store.stored.URL, want)
	}
}
