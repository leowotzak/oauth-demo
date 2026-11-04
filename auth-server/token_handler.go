package main

import (
	"net/http"
	"slices"
	"strings"
	"time"
)

// tokenResponse is a successful token response (RFC 6749 §5.1).
// No refresh_token: §4.4.3 says not to issue one for client_credentials.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// handleToken implements POST /token for the client credentials grant
// (RFC 6749 §4.4). Each check that fails returns its own error code (§5.2).
func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	// Parameters come from the form-encoded body only; r.PostForm ignores
	// the query string.
	r.ParseForm()
	form := r.PostForm

	// 1. Authenticate the client.
	id, secret := clientCredentials(r)
	client, ok := authenticateClient(s.clients, id, secret)
	if !ok {
		writeError(w, http.StatusUnauthorized, errInvalidClient, "client authentication failed")
		return
	}

	// 2. Check the grant type.
	grantType := form.Get("grant_type")
	if grantType == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "missing grant_type")
		return
	}
	if grantType != "client_credentials" {
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType, "only client_credentials is supported")
		return
	}
	if !slices.Contains(client.grantTypes, grantType) {
		writeError(w, http.StatusBadRequest, errUnauthorizedClient, "client may not use this grant_type")
		return
	}

	// 3. Work out the scope.
	scope, disallowed := resolveScope(client, form.Get("scope"))
	if disallowed != "" {
		writeError(w, http.StatusBadRequest, errInvalidScope, "scope "+disallowed+" is not allowed for this client")
		return
	}

	// 4. Issue the token.
	token := s.tokens.issue(client.id, scope, s.tokenTTL)
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenTTL / time.Second),
		Scope:       strings.Join(scope, " "),
	})
}
