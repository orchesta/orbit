package main

import (
	"testing"

	"github.com/aligoren/orbit/internal/domain/entity"
	gitprovider "github.com/aligoren/orbit/internal/infrastructure/git"
)

type stubCloner struct{ gitprovider.Cloner }

func TestClonerFactory(t *testing.T) {
	gh, gl := &stubCloner{}, &stubCloner{}
	f := newClonerFactory(gh, gl)

	if c, err := f(entity.GitProviderGitHub); err != nil || c != gitprovider.Cloner(gh) {
		t.Fatalf("github: %v, %v", c, err)
	}
	if c, err := f(entity.GitProviderGitLab); err != nil || c != gitprovider.Cloner(gl) {
		t.Fatalf("gitlab: %v, %v", c, err)
	}
	c, err := f(entity.GitProviderAzureDevOps)
	if _, ok := c.(*gitprovider.LocalGit); err != nil || !ok {
		t.Fatalf("azuredevops: %T, %v", c, err)
	}
	for _, p := range []entity.GitProvider{"bitbucket", ""} {
		if c, err := f(p); err == nil || c != nil {
			t.Fatalf("%q: want error and no cloner, got %v, %v", p, c, err)
		}
	}
}
