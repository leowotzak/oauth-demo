package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

//go:embed templates/authorize.html
var templateFS embed.FS

// html/template escapes every value it inserts, which matters here: state,
// scope and redirect_uri come straight from the request.
var authorizePage = template.Must(template.ParseFS(templateFS, "templates/authorize.html"))

// scopeDescriptions are what the consent page tells the user each scope means.
var scopeDescriptions = map[string]string{
	"notes:read":   "Read your notes",
	"notes:write":  "Add notes for you",
	"metrics:read": "Read service metrics",
}

// authorizeRequest is a validated authorization request.
type authorizeRequest struct {
	client      *ClientRecord
	redirectURI string
	scope       []string
	state       string
	challenge   string
}

// validateAuthorizeRequest checks an authorization request (RFC 6749 §4.1.1).
// GET checks the URL; POST checks the form again, because hidden form fields
// can be edited. On failure it has already written the response.
func (s *server) validateAuthorizeRequest(w http.ResponseWriter, r *http.Request, p url.Values) (*authorizeRequest, bool) {
	// Phase 1: can we safely redirect back? If the client or redirect URI is
	// bad, show an error page and NEVER redirect (§4.1.2.1). Otherwise anyone
	// could use this server to send users to any URL (an open redirect).
	client, ok := s.clients[p.Get("client_id")]
	if !ok {
		http.Error(w, "Invalid authorization request: unknown client_id.", http.StatusBadRequest)
		return nil, false
	}
	redirectURI := p.Get("redirect_uri")
	if !client.allowsRedirect(redirectURI) {
		http.Error(w, "Invalid authorization request: redirect_uri is not registered for this client.", http.StatusBadRequest)
		return nil, false
	}

	// Phase 2: the redirect URI is trusted now, so other errors go back to the
	// client as redirect_uri?error=...&state=...
	state := p.Get("state")
	fail := func(code, description string) (*authorizeRequest, bool) {
		redirectWithError(w, r, redirectURI, state, code, description)
		return nil, false
	}

	if p.Get("response_type") != "code" {
		return fail(errUnsupportedResponseType, "only response_type=code is supported")
	}
	if !slices.Contains(client.grantTypes, "authorization_code") {
		return fail(errUnauthorizedClient, "client may not use the authorization code flow")
	}
	scope, disallowed := resolveScope(client, p.Get("scope"))
	if disallowed != "" {
		return fail(errInvalidScope, "scope "+disallowed+" is not allowed for this client")
	}
	// PKCE is required (RFC 7636, OAuth 2.1). Only S256: "plain" would send
	// the secret verifier through the browser, which defeats the point.
	if p.Get("code_challenge") == "" || p.Get("code_challenge_method") != "S256" {
		return fail(errInvalidRequest, "PKCE is required: send code_challenge with code_challenge_method=S256")
	}

	return &authorizeRequest{client, redirectURI, scope, state, p.Get("code_challenge")}, true
}

// handleAuthorize implements GET /authorize, the start of the authorization
// code flow. The client sends the user's browser here; if the request is
// valid, the user sees a login and consent page.
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	req, ok := s.validateAuthorizeRequest(w, r, r.URL.Query())
	if !ok {
		return
	}
	renderAuthorizePage(w, req, "", "")
}

// handleAuthorizeSubmit implements POST /authorize: the user pressed Allow or
// Deny on the login page. On Allow with a correct password, it issues an
// authorization code and sends the browser back to the client (§4.1.2).
func (s *server) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	form := r.PostForm

	// 1. Check the request again: the hidden fields could have been edited.
	req, ok := s.validateAuthorizeRequest(w, r, form)
	if !ok {
		return
	}

	// 2. The user said no.
	if form.Get("decision") != "allow" {
		redirectWithError(w, r, req.redirectURI, req.state, errAccessDenied, "the user denied access")
		return
	}

	// 3. Check who they are. On failure, show the page again so they can
	//    retry; don't redirect, so the client learns nothing about failed logins.
	user, ok := authenticateUser(s.users, form.Get("username"), form.Get("password"))
	if !ok {
		renderAuthorizePage(w, req, form.Get("username"), "Invalid username or password.")
		return
	}

	// 4. Issue a short-lived, single-use code tied to everything /token will
	//    check, and send the browser back to the client with it.
	code, err := s.codes.issue(r.Context(), AuthCode{
		ClientID:    req.client.id,
		UserID:      user.id,
		RedirectURI: req.redirectURI,
		Scope:       req.scope,
		Challenge:   req.challenge,
	}, s.codeTTL)
	if err != nil {
		log.Printf("issuing code: %v", err)
		http.Error(w, "The login couldn't be completed right now. Please try again.", http.StatusServiceUnavailable)
		return
	}
	redirectWithParams(w, r, req.redirectURI, url.Values{"code": {code}}, req.state)
}

// renderAuthorizePage shows the login and consent page, with an optional
// error message and a username to fill back in after a failed login.
func renderAuthorizePage(w http.ResponseWriter, req *authorizeRequest, username, errMsg string) {
	type scopeLine struct{ Name, Description string }
	var lines []scopeLine
	for _, sc := range req.scope {
		lines = append(lines, scopeLine{sc, scopeDescriptions[sc]})
	}

	// Never let another site frame this page: it could trick users into
	// clicking Allow (clickjacking, §10.13).
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	authorizePage.Execute(w, map[string]any{
		"ClientID":      req.client.id,
		"RedirectURI":   req.redirectURI,
		"Scope":         strings.Join(req.scope, " "),
		"Scopes":        lines,
		"State":         req.state,
		"CodeChallenge": req.challenge,
		"Username":      username,
		"Error":         errMsg,
	})
}

// redirectWithError sends the browser back to the client with an OAuth error
// (§4.1.2.1).
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	redirectWithParams(w, r, redirectURI, url.Values{"error": {code}, "error_description": {description}}, state)
}

// redirectWithParams sends the browser back to the client's redirect URI with
// the given parameters. state is echoed back unchanged so the client can
// check the response belongs to a request it made.
func redirectWithParams(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values, state string) {
	u, _ := url.Parse(redirectURI) // already checked against the registered list
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
