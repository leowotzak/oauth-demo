package main

import (
	"net/http"
	"strings"
)

// introspectionResponse answers "is this token active, and what does it
// allow?" (RFC 7662 §2.2). An inactive token gets only {"active": false}, so
// callers learn nothing about why.
type introspectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"` // expiry as a Unix timestamp
}

// handleIntrospect implements POST /introspect (RFC 7662). Resource servers
// call it to check the tokens clients send them.
func (s *server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// 1. The caller must authenticate (§2.1), or anyone could probe tokens.
	//    Any registered client may introspect here; a real server would
	//    allow only resource servers.
	id, secret := clientCredentials(r)
	if _, ok := authenticateClient(s.clients, id, secret); !ok {
		writeError(w, http.StatusUnauthorized, errInvalidClient, "client authentication failed")
		return
	}

	// 2. The token to check.
	token := r.PostForm.Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "missing token")
		return
	}

	// 3. Unknown and expired tokens are both just inactive, with 200 OK.
	rec, ok := s.tokens.lookup(token)
	if !ok {
		writeJSON(w, http.StatusOK, introspectionResponse{Active: false})
		return
	}
	writeJSON(w, http.StatusOK, introspectionResponse{
		Active:    true,
		Scope:     strings.Join(rec.scope, " "),
		ClientID:  rec.clientID,
		TokenType: "Bearer",
		Exp:       rec.expiresAt.Unix(),
	})
}
