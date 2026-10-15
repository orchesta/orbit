package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRespondServerErrorHidesDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	RespondServerError(rec, httptest.NewRequest(http.MethodGet, "/x", nil), errors.New(`pq: duplicate key value violates unique constraint "repositories_url_key"`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "repositories_url_key") || !strings.Contains(body, "internal server error") {
		t.Fatalf("body leaks details or lacks the generic message: %s", body)
	}
}

func TestRespondUpstreamErrorHidesDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	RespondUpstreamError(rec, httptest.NewRequest(http.MethodGet, "/x", nil), "failed to fetch GitHub repositories", errors.New("401 Bad credentials: {\"message\":\"token ghp_x\"}"))
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "ghp_x") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}
