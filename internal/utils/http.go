package utils

import (
	"encoding/json"
	"net/http"
)

func WriteJSONResponse(w http.ResponseWriter, statusCode int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteAndReportInternalError(w http.ResponseWriter) {
	// TODO: Log internal errors to Sentry or another monitoring service.
	WriteJSONResponse(w, http.StatusInternalServerError, map[string]any{"error": "an internal error occured"})
}
