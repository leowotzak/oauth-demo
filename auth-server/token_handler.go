package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
)

// tokenResponse is a successful token response (RFC 6749 §5.1). A refresh
// token comes only with logins (authorization code, and each refresh):
// §4.4.3 says not to issue one for client_credentials.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// supportedGrantTypes are the grant_type values this server implements.
var supportedGrantTypes = []string{"client_credentials", "authorization_code", "refresh_token"}

// handleToken implements POST /token for the client credentials grant
// (RFC 6749 §4.4), exchanging authorization codes (§4.1.3), and refreshing
// (§6).
// Each check that fails returns its own error code (§5.2).
func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate the client. Parameters come from the form-encoded body
	//    only; r.PostForm ignores the query string.
	client, ok := s.authenticateCaller(w, r)
	if !ok {
		return
	}
	form := r.PostForm

	// 2. Check the grant type.
	grantType := form.Get("grant_type")
	if grantType == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "missing grant_type")
		return
	}
	if !slices.Contains(supportedGrantTypes, grantType) {
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType, "unsupported grant_type")
		return
	}
	if !slices.Contains(client.grantTypes, grantType) {
		writeError(w, http.StatusBadRequest, errUnauthorizedClient, "client may not use this grant_type")
		return
	}

	// 3. Work out the scope and the user, which each grant decides differently.
	var scope []string
	var userID string           // stays empty for client credentials: no user is involved
	var refreshed *RefreshToken // set for the refresh grant: the token being rotated
	switch grantType {
	case "client_credentials":
		// The client asks for scopes itself.
		var disallowed string
		scope, disallowed = resolveScope(client, form.Get("scope"))
		if disallowed != "" {
			writeError(w, http.StatusBadRequest, errInvalidScope, "scope "+disallowed+" is not allowed for this client")
			return
		}

	case "authorization_code":
		// The scope is whatever the user approved, recorded with the code.
		code, ok := s.redeemCode(w, r, client)
		if !ok {
			return
		}
		scope = code.Scope
		userID = code.UserID // the token acts for the user who logged in

	case "refresh_token":
		// The same login continues: same user, and the approved scope or less.
		rec, ok := s.useRefreshToken(w, r, client)
		if !ok {
			return
		}
		refreshed = rec
		userID = rec.UserID
		scope = rec.Scope
		if raw := form.Get("scope"); raw != "" {
			// §6: a client may ask for less than was approved, never more.
			scope = strings.Fields(raw)
			for _, sc := range scope {
				if !slices.Contains(rec.Scope, sc) {
					writeError(w, http.StatusBadRequest, errInvalidScope, "scope "+sc+" was not part of the original grant")
					return
				}
			}
		}
	}

	// 4. Issue the access token.
	token := s.issueAccessToken(client.id, userID, scope)
	resp := tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenTTL / time.Second),
		Scope:       strings.Join(scope, " "),
	}

	// 5. And a refresh token, for logins by clients allowed to refresh: a new
	//    family after a code exchange, or the next token in the family after a
	//    refresh (rotation). The refresh token keeps the family's full scope,
	//    even when this access token was narrowed (§6).
	var err error
	switch {
	case refreshed != nil:
		resp.RefreshToken, err = s.rotate(r.Context(), form.Get("refresh_token"), *refreshed, token)
	case grantType == "authorization_code" && slices.Contains(client.grantTypes, "refresh_token"):
		resp.RefreshToken, err = s.startFamily(r.Context(), client.id, userID, scope, token)
	}
	if err != nil {
		log.Printf("storing refresh token: %v", err)
		writeError(w, http.StatusServiceUnavailable, errTemporarilyUnavailable, "try again shortly")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// useRefreshToken checks a refresh request (RFC 6749 §6) and returns the
// token's record, which is now used up. Failures are invalid_grant; on
// failure it has already written the response.
func (s *server) useRefreshToken(w http.ResponseWriter, r *http.Request, client *ClientRecord) (*RefreshToken, bool) {
	token := r.PostForm.Get("refresh_token")
	if token == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "missing refresh_token")
		return nil, false
	}
	rec, err := s.redeemRefresh(r.Context(), token)
	switch {
	case errors.Is(err, errReuse):
		log.Printf("refresh token reused: revoked its family (client %s)", client.id)
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token was already used; this login has been revoked")
		return nil, false
	case err != nil:
		log.Printf("redeeming refresh token: %v", err)
		writeError(w, http.StatusServiceUnavailable, errTemporarilyUnavailable, "try again shortly")
		return nil, false
	case rec == nil:
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token is invalid or expired")
		return nil, false
	case rec.ClientID != client.id:
		// Like codes, a refresh token only works for the client it was issued to.
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token was issued to another client")
		return nil, false
	}
	return rec, true
}

// redeemCode checks an authorization code exchange (RFC 6749 §4.1.3) and
// returns the code's record. Every failure is invalid_grant (§5.2), with a
// description saying which check failed. On failure it has already written
// the response.
func (s *server) redeemCode(w http.ResponseWriter, r *http.Request, client *ClientRecord) (*AuthCode, bool) {
	form := r.PostForm
	fail := func(description string) (*AuthCode, bool) {
		writeError(w, http.StatusBadRequest, errInvalidGrant, description)
		return nil, false
	}

	if form.Get("code") == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "missing code")
		return nil, false
	}

	// 1. The code exists, hasn't expired and hasn't been used. Redeeming it
	//    also deletes it, so even a failed attempt below burns it: an attacker
	//    with a stolen code gets one try at guessing the PKCE verifier.
	code, err := s.codes.redeem(r.Context(), form.Get("code"))
	if err != nil {
		// Fail closed: without Redis, the code can't be checked.
		log.Printf("redeeming code: %v", err)
		writeError(w, http.StatusServiceUnavailable, errTemporarilyUnavailable, "try again shortly")
		return nil, false
	}
	if code == nil {
		return fail("code is invalid, expired or already used")
	}

	// 2. It was issued to this client. A code for client1 can't be spent by
	//    another client, even one that authenticated correctly.
	if code.ClientID != client.id {
		return fail("code was issued to another client")
	}

	// 3. redirect_uri is identical to the one used at /authorize (§4.1.3).
	if form.Get("redirect_uri") != code.RedirectURI {
		return fail("redirect_uri does not match the authorization request")
	}

	// 4. PKCE (RFC 7636 §4.6): only the app that started the login knows the
	//    verifier whose hash is the stored challenge.
	if !pkceMatches(form.Get("code_verifier"), code.Challenge) {
		return fail("code_verifier does not match the code_challenge")
	}

	return code, true
}

// pkceMatches checks a PKCE verifier against an S256 challenge:
// BASE64URL(SHA256(verifier)) must equal the challenge.
func pkceMatches(verifier, challenge string) bool {
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
