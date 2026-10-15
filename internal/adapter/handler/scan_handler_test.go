package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/usecase/scan"
)

type scanTestRepos struct {
	repository.RepositoryRepo
	exists bool
	name   string // repository name; "r" when empty
}

func (s scanTestRepos) GetByID(_ context.Context, id uuid.UUID) (*entity.Repository, error) {
	if !s.exists {
		return nil, nil
	}
	name := s.name
	if name == "" {
		name = "r"
	}
	r := entity.NewRepository(name, "https://github.com/o/r", entity.GitProviderGitHub, "")
	r.ID = id
	return r, nil
}

func (scanTestRepos) SetNextScanAt(context.Context, uuid.UUID, time.Time) error { return nil }

type scanTestQueue struct {
	repository.ScanResultRepo
	active *entity.ScanResult
}

func (q *scanTestQueue) Enqueue(_ context.Context, s *entity.ScanResult) (*entity.ScanResult, bool, error) {
	if q.active != nil {
		return q.active, false, nil
	}
	q.active = s
	return s, true, nil
}

func newScanRouter(exists bool, queue *scanTestQueue) http.Handler {
	uc := scan.NewUseCase(scanTestRepos{exists: exists}, queue, nil, nil, nil, nil, nil, scan.Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := chi.NewRouter()
	NewScanHandler(uc).RegisterRoutes(r)
	return r
}

func triggerScan(h http.Handler, id uuid.UUID) (*httptest.ResponseRecorder, string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/repositories/"+id.String()+"/scan", nil))
	var body struct {
		Data struct {
			ScanID string `json:"scan_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body.Data.ScanID
}

func TestTriggerScanUnknownRepositoryIs404(t *testing.T) {
	rec, _ := triggerScan(newScanRouter(false, &scanTestQueue{}), uuid.New())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestTriggerScanReturnsExistingScan(t *testing.T) {
	h := newScanRouter(true, &scanTestQueue{})
	id := uuid.New()
	first, firstID := triggerScan(h, id)
	second, secondID := triggerScan(h, id)
	if first.Code != http.StatusAccepted || second.Code != http.StatusAccepted {
		t.Fatalf("status = %d, %d; want 202", first.Code, second.Code)
	}
	if firstID == "" || firstID != secondID {
		t.Fatalf("scan ids %q, %q; a second trigger must return the queued scan", firstID, secondID)
	}
	for i, tc := range []struct {
		rec    *httptest.ResponseRecorder
		queued bool
	}{{first, true}, {second, false}} {
		var body struct {
			Data struct {
				Queued *bool  `json:"queued"`
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(tc.rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("trigger %d: decode body: %v", i+1, err)
		}
		if body.Data.Queued == nil || *body.Data.Queued != tc.queued {
			t.Fatalf("trigger %d: queued = %v, want %v", i+1, body.Data.Queued, tc.queued)
		}
		if body.Data.Status != string(entity.ScanStatusPending) {
			t.Fatalf("trigger %d: status = %q, want %q", i+1, body.Data.Status, entity.ScanStatusPending)
		}
	}
}
