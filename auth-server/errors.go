package main

import (
	"encoding/json"
	"net/http"
)

// OAuth error codes (RFC 6749 §4.1.2.1 for /authorize, §5.2 for /token).
const (
	errInvalidRequest          = "invalid_request"
	errInvalidClient           = "invalid_client"
	errUnauthorizedClient      = "unauthorized_client"
	errUnsupportedGrantType    = "unsupported_grant_type"
	errUnsupportedResponseType = "unsupported_response_type"
	errInvalidScope            = "invalid_scope"
	errInvalidGrant            = "invalid_grant"
	errAccessDenied            = "access_denied"
	errTemporarilyUnavailable  = "temporarily_unavailable" // a dependency (Redis) is down
)

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeError sends an OAuth error response (RFC 6749 §5.2).
func writeError(w http.ResponseWriter, status int, code, description string) {
	if status == http.StatusUnauthorized {
		// HTTP requires a 401 to say how to authenticate.
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
	}
	writeJSON(w, status, errorResponse{Error: code, ErrorDescription: description})
}

// writeJSON sends a JSON response. Token responses must not be cached (§5.1).
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
