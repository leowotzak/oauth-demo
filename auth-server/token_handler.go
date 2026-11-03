package main

import (
	"mime"
	"net/http"
	"net/url"
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

// handleToken implements POST /token (RFC 6749 §3.2). The router only sends
// POST requests here; anything else gets 405 Method Not Allowed.
//
// The checks run in a fixed order, and each failure has its own error code:
//
//  1. request format     → invalid_request
//  2. client credentials → invalid_client (401)
//  3. grant type         → invalid_request / unsupported_grant_type / unauthorized_client
//  4. scope              → invalid_scope
//  5. issue the token
func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	// 1. Request format.

	// Parameters must be form-encoded in the body (RFC 6749 §3.2, Appendix B).
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed request body")
		return
	}
	// Read only r.PostForm (the body). r.Form would also include the query
	// string, and parameters there must be ignored.
	form := r.PostForm

	// Parameters must not be included more than once (RFC 6749 §3.2).
	for name, values := range form {
		if len(values) > 1 {
			writeError(w, http.StatusBadRequest, errInvalidRequest, "parameter "+name+" is repeated")
			return
		}
	}

	// 2. Client credentials.

	id, secret, ok := clientCredentials(r, form)
	if !ok {
		// Covers both "used two methods" and "Basic credentials didn't decode".
		writeError(w, http.StatusBadRequest, errInvalidRequest, "use exactly one client authentication method")
		return
	}
	if id == "" {
		writeError(w, http.StatusUnauthorized, errInvalidClient, "client authentication required")
		return
	}
	client, ok := authenticateClient(s.clients, id, secret)
	if !ok {
		// Same message for unknown client and wrong secret.
		writeError(w, http.StatusUnauthorized, errInvalidClient, "client authentication failed")
		return
	}

	// 3. Grant type.

	grantType := form.Get("grant_type")
	switch {
	case grantType == "":
		writeError(w, http.StatusBadRequest, errInvalidRequest, "missing grant_type")
		return
	case !knownGrantTypes[grantType]:
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType, "unsupported grant_type")
		return
	case !client.allowedGrantTypes[grantType]:
		writeError(w, http.StatusBadRequest, errUnauthorizedClient, "client may not use this grant_type")
		return
	}
	// knownGrantTypes lists every grant this server will eventually support;
	// only client_credentials is implemented so far.
	if grantType != "client_credentials" {
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType, "grant_type not implemented yet")
		return
	}

	// 4. Scope.

	scope, ok := resolveScope(client, form)
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidScope, "requested scope is invalid or not allowed for this client")
		return
	}

	// 5. Issue the token.

	token, _ := s.tokens.issue(client.id, scope, s.tokenTTL)
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenTTL / time.Second),
		// Always echo the granted scope. §5.1 only requires it when it
		// differs from the request, but always sending it is unambiguous.
		Scope: strings.Join(scope, " "),
	})
}

// clientCredentials extracts the client ID and secret from the request
// (RFC 6749 §2.3.1). It supports HTTP Basic (client_secret_basic) and body
// parameters (client_secret_post). ok is false if the request uses both
// methods (§2.3 forbids more than one) or the Basic credentials don't decode.
// An empty id with ok=true means no credentials were sent.
func clientCredentials(r *http.Request, form url.Values) (id, secret string, ok bool) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	_, hasBodySecret := form["client_secret"]
	_, hasBodyID := form["client_id"]

	if hasBasic {
		if hasBodySecret || hasBodyID {
			return "", "", false
		}
		// Quirk of §2.3.1: the ID and secret are form-urlencoded before being
		// base64-encoded, so they have to be decoded again here.
		var err1, err2 error
		id, err1 = url.QueryUnescape(basicID)
		secret, err2 = url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil {
			return "", "", false
		}
		return id, secret, true
	}

	return form.Get("client_id"), form.Get("client_secret"), true
}

// resolveScope works out which scopes to grant (RFC 6749 §3.3).
//   - scope omitted: the client's default scopes.
//   - scope present: split on single spaces; an empty entry (from "", a
//     leading/trailing space or a double space) is malformed; duplicates are
//     dropped; every scope must be allowed for the client.
//
// This server rejects a disallowed scope rather than silently granting less.
func resolveScope(client *ClientRecord, form url.Values) ([]string, bool) {
	raw, present := form["scope"]
	if !present {
		return client.defaultScopes, true
	}

	var granted []string
	seen := map[string]bool{}
	for _, s := range strings.Split(raw[0], " ") {
		if s == "" || !client.allowedScopes[s] {
			return nil, false
		}
		if !seen[s] {
			seen[s] = true
			granted = append(granted, s)
		}
	}
	return granted, true
}
