package handler

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/aligoren/orbit/internal/domain/entity"
	domainrepo "github.com/aligoren/orbit/internal/domain/repository"
	"github.com/aligoren/orbit/internal/usecase/repo"
)

func TestPlanImportSkipsExistingAndRepeatedRepositories(t *testing.T) {
	items := []importItem{
		{Name: "old", URL: "https://github.com/o/Old.git"},
		{Name: "new", URL: "https://github.com/o/new"},
		{Name: "new-again", URL: "https://github.com/o/new/"},
	}
	create, skipped := planImport(items, map[string]bool{"https://github.com/o/old": true})
	if len(create) != 1 || create[0].Name != "new" {
		t.Fatalf("create = %+v, want only new", create)
	}
	if !reflect.DeepEqual(skipped, []string{"old", "new-again"}) {
		t.Fatalf("skipped = %v", skipped)
	}

	create, skipped = planImport(items[1:2], map[string]bool{})
	if len(create) != 1 || skipped == nil || len(skipped) != 0 {
		t.Fatalf("nothing existing: create %v, skipped %#v (want empty, non-nil)", create, skipped)
	}
}

type fakeCreator struct {
	duplicate map[string]bool // URLs whose Create reports ErrDuplicate
}

func (f fakeCreator) Create(_ context.Context, in repo.CreateInput) (*entity.Repository, error) {
	if f.duplicate[in.URL] {
		return nil, fmt.Errorf("failed to create repository: %w", domainrepo.ErrDuplicate)
	}
	return entity.NewRepository(in.Name, in.URL, in.Provider, in.AuthToken), nil
}

func TestCreateImportedSkipsRepositoriesStoredByAConcurrentImport(t *testing.T) {
	items := []importItem{
		{Name: "a", URL: "https://github.com/o/a"},
		{Name: "raced", URL: "https://github.com/o/raced"},
		{Name: "b", URL: "https://github.com/o/b"},
	}
	creator := fakeCreator{duplicate: map[string]bool{"https://github.com/o/raced": true}}
	created, skipped, err := createImported(context.Background(), creator, entity.GitProviderGitHub, nil, "tok", items)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 2 || created[0].Name != "a" || created[1].Name != "b" {
		t.Fatalf("created = %+v, want a and b", created)
	}
	if !reflect.DeepEqual(skipped, []string{"raced"}) {
		t.Fatalf("skipped = %v, want [raced]", skipped)
	}
}
