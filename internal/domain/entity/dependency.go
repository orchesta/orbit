package entity

import (
	"time"

	"github.com/google/uuid"
)

// Ecosystem represents a package ecosystem.
type Ecosystem string

const (
	EcosystemNpm   Ecosystem = "npm"
	EcosystemPyPI  Ecosystem = "PyPI"
	EcosystemNuGet Ecosystem = "NuGet"
	EcosystemGo    Ecosystem = "Go"
)

// UpdateType represents the type of version update available.
type UpdateType string

const (
	UpdateTypeMajor UpdateType = "major"
	UpdateTypeMinor UpdateType = "minor"
	UpdateTypePatch UpdateType = "patch"
	UpdateTypeNone  UpdateType = "none"
)

// Dependency represents a package dependency found in a repository.
type Dependency struct {
	ID             uuid.UUID `json:"id"`
	RepositoryID   uuid.UUID `json:"repository_id"`
	ScanResultID   uuid.UUID `json:"scan_result_id"`
	Name           string    `json:"name"`
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	Ecosystem      Ecosystem `json:"ecosystem"`
	ManifestFile   string    `json:"manifest_file"`
	IsOutdated     bool      `json:"is_outdated"`
	IsDirect       bool      `json:"is_direct"`   // Direct vs transitive dependency
	IsResolved     bool      `json:"is_resolved"` // Version comes from a lockfile (exact), not a manifest range
	IsDev          bool      `json:"is_dev"`      // Development-only dependency
	// Via names the direct dependencies that pull a dependency in, when the
	// lockfile records the graph (npm package-lock.json v2 and v3). The
	// engine sets it; the server does not store it.
	Via        []string   `json:"via,omitempty"`
	UpdateType UpdateType `json:"update_type"`
	// License is the package's license as a normalised SPDX expression,
	// or "" when it is not known.
	License       string    `json:"license"`
	LastCheckedAt time.Time `json:"last_checked_at"`
}

// NewDependency creates a new Dependency.
func NewDependency(repoID, scanID uuid.UUID, name, currentVersion, manifestFile string, ecosystem Ecosystem) *Dependency {
	return &Dependency{
		ID:             uuid.New(),
		RepositoryID:   repoID,
		ScanResultID:   scanID,
		Name:           name,
		CurrentVersion: currentVersion,
		Ecosystem:      ecosystem,
		ManifestFile:   manifestFile,
		IsDirect:       true,
		UpdateType:     UpdateTypeNone,
		LastCheckedAt:  time.Now().UTC(),
	}
}
