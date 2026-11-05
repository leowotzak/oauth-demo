package main

import (
	"context"
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
	Sub      string `json:"sub"` // the user the token acts for; empty for client credentials
}

// owner is whose notes a token gives access to: the user it acts for, or,
// for client credentials tokens (no user), the client itself.
func (i introspection) owner() string {
	if i.Sub != "" {
		return i.Sub
	}
	return "client:" + i.ClientID
}

// ownerKey stores the token's owner in the request context, so handlers know
// whose notes to use without touching tokens themselves.
type ownerKey struct{}

func ownerFrom(r *http.Request) string {
	return r.Context().Value(ownerKey{}).(string)
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
//	no token          → 401, WWW-Authenticate: Bearer realm="notes"
//	inactive token    → 401, … error="invalid_token"
//	missing the scope → 403, … error="insufficient_scope", scope="…"
func (s *server) requireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Read the token from "Authorization: Bearer <token>" (§2.1).
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			bearerError(w, http.StatusUnauthorized, `Bearer realm="notes"`, "missing bearer token")
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
			bearerError(w, http.StatusUnauthorized, `Bearer realm="notes", error="invalid_token"`, "token is unknown or expired")
			return
		}

		// 3. Check it carries the scope this endpoint needs.
		if !slices.Contains(strings.Fields(info.Scope), scope) {
			bearerError(w, http.StatusForbidden, `Bearer realm="notes", error="insufficient_scope", scope="`+scope+`"`, "token lacks scope "+scope)
			return
		}

		// 4. Pass on whose data this request is about.
		next(w, r.WithContext(context.WithValue(r.Context(), ownerKey{}, info.owner())))
	}
}

// bearerError sends an RFC 6750 §3 error. The error code goes in the
// WWW-Authenticate header (the "challenge"); the plain-text body is just for
// people reading curl output.
func bearerError(w http.ResponseWriter, status int, challenge, message string) {
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, message, status)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
