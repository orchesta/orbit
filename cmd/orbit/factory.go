package main

import (
	"fmt"

	"github.com/orchesta/orbit/internal/domain/entity"
	gitprovider "github.com/orchesta/orbit/internal/infrastructure/git"
)

// newClonerFactory picks the cloner for a repository's provider. Unknown
// providers are an error, never a silent fallback to another provider.
func newClonerFactory(gh, gl gitprovider.Cloner) func(entity.GitProvider) (gitprovider.Cloner, error) {
	return func(provider entity.GitProvider) (gitprovider.Cloner, error) {
		switch provider {
		case entity.GitProviderGitHub:
			return gh, nil
		case entity.GitProviderGitLab:
			return gl, nil
		case entity.GitProviderAzureDevOps:
			return gitprovider.NewLocalGit(), nil
		default:
			return nil, fmt.Errorf("unsupported git provider %q", provider)
		}
	}
}
