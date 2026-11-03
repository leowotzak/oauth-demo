package main

import (
	"encoding/json"
	"net/http"
)

// OAuth error codes for the token endpoint (RFC 6749 §5.2).
const (
	errInvalidRequest       = "invalid_request"
	errInvalidClient        = "invalid_client"
	errInvalidGrant         = "invalid_grant"
	errUnauthorizedClient   = "unauthorized_client"
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidScope         = "invalid_scope"
)

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeError sends an OAuth error response (RFC 6749 §5.2): a JSON body with
// "error" and an optional "error_description", never cached.
func writeError(w http.ResponseWriter, status int, code, description string) {
	// invalid_client is a 401, and HTTP requires a 401 to say how to
	// authenticate (RFC 9110 §15.5.2). This server accepts HTTP Basic.
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
	}
	writeJSON(w, status, errorResponse{Error: code, ErrorDescription: description})
}

// writeJSON sends a JSON body with the headers RFC 6749 §5.1 requires on
// token responses, so neither tokens nor errors end up in a cache.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
