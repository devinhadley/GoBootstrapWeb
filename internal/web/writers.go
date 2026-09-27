// Package web provides shared http utilities.
package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// maxJSONBodyBytes caps how much of a request body DecodeJSONBodyOrWriteError will read.
const maxJSONBodyBytes = 5 << 20 // 5 MiB

func WriteJSONResponse(w http.ResponseWriter, statusCode int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteAndReportInternalError(w http.ResponseWriter, err error) {
	// TODO: Report internal errors to Sentry or another monitoring service.
	slog.Error("internal error", "err", err)
	WriteJSONResponse(w, http.StatusInternalServerError, map[string]any{"error": "an internal error occurred"})
}

func DecodeJSONBodyOrWriteError[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var body T
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			WriteJSONResponse(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large"})
			return body, false
		}
		WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return body, false
	}
	return body, true
}
