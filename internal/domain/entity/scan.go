package entity

import (
	"time"

	"github.com/google/uuid"
)

// ScanStatus represents the current status of a scan.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

// ScanResult represents the result of a repository scan.
type ScanResult struct {
	ID             uuid.UUID     `json:"id"`
	RepositoryID   uuid.UUID     `json:"repository_id"`
	Status         ScanStatus    `json:"status"`
	TotalDeps      int           `json:"total_deps"`
	OutdatedDeps   int           `json:"outdated_deps"`
	VulnerableDeps int           `json:"vulnerable_deps"`
	TotalVulns     int           `json:"total_vulns"`
	Duration       time.Duration `json:"duration"`
	Error          *string       `json:"error,omitempty"`
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    *time.Time    `json:"completed_at,omitempty"`
	// Attempt is the claim number from the queue; it fences writes by a
	// worker that lost the scan.
	Attempt int `json:"-"`
}

// NewScanResult creates a new ScanResult in pending state.
func NewScanResult(repoID uuid.UUID) *ScanResult {
	return &ScanResult{
		ID:           uuid.New(),
		RepositoryID: repoID,
		Status:       ScanStatusPending,
		StartedAt:    time.Now().UTC(),
	}
}

// Start marks the scan as running.
func (s *ScanResult) Start() {
	s.Status = ScanStatusRunning
	now := time.Now().UTC()
	s.StartedAt = now
}

// Complete marks the scan as completed with the given stats.
func (s *ScanResult) Complete(totalDeps, outdatedDeps, vulnerableDeps, totalVulns int) {
	s.Status = ScanStatusCompleted
	now := time.Now().UTC()
	s.CompletedAt = &now
	s.Duration = now.Sub(s.StartedAt)
	s.TotalDeps = totalDeps
	s.OutdatedDeps = outdatedDeps
	s.VulnerableDeps = vulnerableDeps
	s.TotalVulns = totalVulns
}

// Fail marks the scan as failed with the given error.
func (s *ScanResult) Fail(err string) {
	s.Status = ScanStatusFailed
	now := time.Now().UTC()
	s.CompletedAt = &now
	s.Duration = now.Sub(s.StartedAt)
	s.Error = &err
}
