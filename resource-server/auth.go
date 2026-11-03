package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// introspection is the part of the auth server's /introspect answer
// (RFC 7662 §2.2) this service uses.
type introspection struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
}

// introspect asks the auth server whether a token is active and what it
// allows. This service authenticates as its own client (HTTP Basic).
func (s *server) introspect(token string) (introspection, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequest(http.MethodPost, s.introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return introspection{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.clientID, s.clientSecret)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return introspection{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return introspection{}, fmt.Errorf("introspection returned %s", resp.Status)
	}

	var result introspection
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}

// requireScope wraps a handler so it only runs for requests carrying an
// active Bearer token with the given scope (RFC 6750).
//
//	no token          → 401, WWW-Authenticate: Bearer
//	inactive token    → 401, error="invalid_token"
//	missing the scope → 403, error="insufficient_scope"
func (s *server) requireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Read the token from "Authorization: Bearer <token>" (§2.1).
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			bearerError(w, http.StatusUnauthorized, "", "", "missing bearer token")
			return
		}

		// 2. Ask the auth server whether it's active.
		info, err := s.introspect(token)
		if err != nil {
			log.Printf("introspection failed: %v", err)
			http.Error(w, "cannot check token right now", http.StatusServiceUnavailable)
			return
		}
		if !info.Active {
			bearerError(w, http.StatusUnauthorized, "invalid_token", "", "token is unknown or expired")
			return
		}

		// 3. Check it carries the scope this endpoint needs.
		if !slices.Contains(strings.Fields(info.Scope), scope) {
			bearerError(w, http.StatusForbidden, "insufficient_scope", scope, "token lacks scope "+scope)
			return
		}

		next(w, r)
	}
}

// bearerError sends an RFC 6750 §3 error. The error code goes in the
// WWW-Authenticate header; the JSON body is just for people reading curl output.
func bearerError(w http.ResponseWriter, status int, code, scope, description string) {
	challenge := `Bearer realm="notes"`
	if code != "" {
		challenge += fmt.Sprintf(`, error="%s"`, code)
	}
	if scope != "" {
		challenge += fmt.Sprintf(`, scope="%s"`, scope)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	body := map[string]string{"error_description": description}
	if code != "" {
		body["error"] = code
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
