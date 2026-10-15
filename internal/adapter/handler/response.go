package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// apiResponse is a standard API response wrapper.
type apiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// RespondJSON sends a JSON response.
func RespondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if statusCode == http.StatusNoContent {
		return
	}

	resp := apiResponse{
		Success: statusCode >= 200 && statusCode < 300,
		Data:    data,
	}

	json.NewEncoder(w).Encode(resp)
}

// RespondError sends an error JSON response.
func RespondError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := apiResponse{
		Success: false,
		Error:   message,
	}

	json.NewEncoder(w).Encode(resp)
}

// RespondServerError logs err with the request ID and sends the client a
// generic 500, so database and upstream details never reach the response.
func RespondServerError(w http.ResponseWriter, r *http.Request, err error) {
	reqID := middleware.GetReqID(r.Context())
	slog.ErrorContext(r.Context(), "request failed",
		slog.String("request_id", reqID), slog.String("path", r.URL.Path), slog.String("error", err.Error()))
	msg := "internal server error"
	if reqID != "" {
		msg += " (request id: " + reqID + ")"
	}
	RespondError(w, http.StatusInternalServerError, msg)
}

// RespondUpstreamError logs err and sends a 502 carrying only message, since
// upstream error bodies can echo credentials or internal details.
func RespondUpstreamError(w http.ResponseWriter, r *http.Request, message string, err error) {
	slog.ErrorContext(r.Context(), message,
		slog.String("request_id", middleware.GetReqID(r.Context())), slog.String("error", err.Error()))
	RespondError(w, http.StatusBadGateway, message)
}

// decodeJSON reads the request body into v. On failure it writes the error
// response (413 when the body exceeded the size limit, 400 otherwise) and
// returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
	} else {
		RespondError(w, http.StatusBadRequest, "invalid request body")
	}
	return false
}
