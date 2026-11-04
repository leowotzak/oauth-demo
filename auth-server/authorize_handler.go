package main

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

//go:embed templates/authorize.html
var templateFS embed.FS

// html/template escapes every value it inserts, which matters here: state,
// scope and redirect_uri come straight from the URL.
var authorizePage = template.Must(template.ParseFS(templateFS, "templates/authorize.html"))

// scopeDescriptions are what the consent page tells the user each scope means.
var scopeDescriptions = map[string]string{
	"notes:read":   "Read your notes",
	"notes:write":  "Add notes for you",
	"metrics:read": "Read service metrics",
}

// handleAuthorize implements GET /authorize, the start of the authorization
// code flow (RFC 6749 §4.1.1). The client sends the user's browser here; if
// the request is valid, the user sees a login and consent page.
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Phase 1: can we safely redirect back? If the client or redirect URI is
	// bad, show an error page and NEVER redirect (§4.1.2.1). Otherwise anyone
	// could use this server to send users to any URL (an open redirect).
	client, ok := s.clients[q.Get("client_id")]
	if !ok {
		http.Error(w, "Invalid authorization request: unknown client_id.", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !client.allowsRedirect(redirectURI) {
		http.Error(w, "Invalid authorization request: redirect_uri is not registered for this client.", http.StatusBadRequest)
		return
	}

	// Phase 2: the redirect URI is trusted now, so other errors go back to the
	// client as redirect_uri?error=...&state=...
	state := q.Get("state")
	fail := func(code, description string) {
		redirectWithError(w, r, redirectURI, state, code, description)
	}

	if q.Get("response_type") != "code" {
		fail(errUnsupportedResponseType, "only response_type=code is supported")
		return
	}
	if !slices.Contains(client.grantTypes, "authorization_code") {
		fail(errUnauthorizedClient, "client may not use the authorization code flow")
		return
	}
	scope, disallowed := resolveScope(client, q.Get("scope"))
	if disallowed != "" {
		fail(errInvalidScope, "scope "+disallowed+" is not allowed for this client")
		return
	}
	// PKCE is required (RFC 7636, OAuth 2.1). Only S256: "plain" would send
	// the secret verifier through the browser, which defeats the point.
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		fail(errInvalidRequest, "PKCE is required: send code_challenge with code_challenge_method=S256")
		return
	}

	// Everything checks out: show the login and consent page.
	type scopeLine struct{ Name, Description string }
	var lines []scopeLine
	for _, sc := range scope {
		lines = append(lines, scopeLine{sc, scopeDescriptions[sc]})
	}

	// Never let another site frame this page: it could trick users into
	// clicking Allow (clickjacking, §10.13).
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	authorizePage.Execute(w, map[string]any{
		"ClientID":            client.id,
		"RedirectURI":         redirectURI,
		"Scope":               strings.Join(scope, " "),
		"Scopes":              lines,
		"State":               state,
		"CodeChallenge":       q.Get("code_challenge"),
		"CodeChallengeMethod": "S256",
	})
}

// redirectWithError sends the browser back to the client with an OAuth error
// (§4.1.2.1). state is echoed back unchanged so the client can match it.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, _ := url.Parse(redirectURI) // already checked against the registered list
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
