package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

//go:embed templates/index.html
var templateFS embed.FS

var indexPage = template.Must(template.ParseFS(templateFS, "templates/index.html"))

// page is what the single page shows: a login button, or the user's notes.
type page struct {
	LoggedIn bool
	Owner    string
	Notes    []string
	Message  string
}

func render(w http.ResponseWriter, status int, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	indexPage.Execute(w, p)
}

// handleHome shows the login button, or the user's notes if they're logged in.
func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	id := sessionID(w, r)
	tok, err := a.tokenOf(r.Context(), id)
	if err != nil {
		sessionsUnavailable(w, err)
		return
	}
	if tok == nil {
		render(w, http.StatusOK, page{})
		return
	}
	notes, err := a.callNotes(r.Context(), tok, http.MethodGet, nil)
	if errors.Is(err, errTokenRejected) {
		a.forgetToken(r.Context(), id)
		render(w, http.StatusOK, page{Message: "Your session expired. Log in again."})
		return
	}
	if err != nil {
		log.Printf("listing notes: %v", err)
		render(w, http.StatusBadGateway, page{LoggedIn: true, Message: "Couldn't load your notes. Is the notes API running?"})
		return
	}
	render(w, http.StatusOK, page{LoggedIn: true, Owner: notes.Owner, Notes: notes.Notes})
}

// handleLogin starts the authorization code flow: it remembers a fresh state
// and PKCE verifier for this session, then sends the browser to the auth server.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := rand.Text()
	verifier := oauth2.GenerateVerifier()
	if err := a.saveLogin(r.Context(), sessionID(w, r), pendingLogin{state, verifier}); err != nil {
		sessionsUnavailable(w, err)
		return
	}

	// AuthCodeURL builds /authorize?response_type=code&client_id&redirect_uri
	// &scope&state; S256ChallengeOption adds code_challenge=BASE64URL(SHA256(verifier))
	// and code_challenge_method=S256. Only the challenge goes through the browser.
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// handleCallback is where the auth server sends the browser back, with
// ?code=…&state=… or ?error=…&state=…
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	id := sessionID(w, r)
	q := r.URL.Query()

	// state and verifier are single use: take them out of Redis now,
	// whatever happens next.
	login, ok, err := a.takeLogin(r.Context(), id)
	if err != nil {
		sessionsUnavailable(w, err)
		return
	}

	// 1. Only accept a response to a login this browser started (CSRF).
	//    Checked before anything else, including errors.
	if !ok || q.Get("state") != login.State {
		render(w, http.StatusBadRequest, page{Message: "Login failed: this response doesn't match a login started here. Try logging in again."})
		return
	}

	// 2. The user pressed Deny, or the auth server rejected the request.
	if e := q.Get("error"); e != "" {
		render(w, http.StatusOK, page{Message: fmt.Sprintf("Login didn't complete (%s).", e)})
		return
	}

	// 3. Exchange the code for a token, over the back channel. The library
	//    sends grant_type=authorization_code, the code, redirect_uri and
	//    code_verifier, authenticating with client1's secret via HTTP Basic.
	tok, err := a.oauth.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(login.Verifier))
	if err != nil {
		log.Printf("code exchange failed: %v", err)
		render(w, http.StatusBadGateway, page{Message: "Login failed: the authorization code couldn't be exchanged. Try logging in again."})
		return
	}

	// 4. Keep the token on the server; the browser only has its session cookie.
	if err := a.saveToken(r.Context(), id, tok); err != nil {
		sessionsUnavailable(w, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleAddNote adds a note through the notes API with the stored token.
func (a *app) handleAddNote(w http.ResponseWriter, r *http.Request) {
	id := sessionID(w, r)
	tok, err := a.tokenOf(r.Context(), id)
	if err != nil {
		sessionsUnavailable(w, err)
		return
	}
	if tok == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	body, _ := json.Marshal(map[string]string{"text": r.PostFormValue("text")})
	_, err = a.callNotes(r.Context(), tok, http.MethodPost, body)
	if errors.Is(err, errTokenRejected) {
		a.forgetToken(r.Context(), id)
	} else if err != nil {
		log.Printf("adding note: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout revokes the token at the auth server, so it stops working
// everywhere straight away, then forgets it here.
func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	id := sessionID(w, r)
	tok, err := a.tokenOf(r.Context(), id)
	if err != nil {
		sessionsUnavailable(w, err)
		return
	}
	if tok != nil {
		if err := a.revoke(r.Context(), tok.AccessToken); err != nil {
			// Still log the user out here; the token expires within 15 minutes.
			log.Printf("revoking token: %v", err)
		}
	}
	a.forgetToken(r.Context(), id)
	http.Redirect(w, r, "/", http.StatusFound)
}

// revoke asks the auth server to revoke a token (RFC 7009), authenticating
// as this client. x/oauth2 has no revocation call, so this is a plain request
// to the /revoke next to the /token endpoint.
func (a *app) revoke(ctx context.Context, token string) error {
	revokeURL := strings.TrimSuffix(a.oauth.Endpoint.TokenURL, "/token") + "/revoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL,
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.oauth.ClientID, a.oauth.ClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke returned %s", resp.Status)
	}
	return nil
}

// sessionsUnavailable reports that sessions can't be read or saved (Redis is
// down). Without them nobody can log in safely, so stop here.
func sessionsUnavailable(w http.ResponseWriter, err error) {
	log.Printf("sessions unavailable: %v", err)
	render(w, http.StatusServiceUnavailable, page{Message: "Sign-in is unavailable right now. Please try again shortly."})
}

// errTokenRejected means the notes API refused the token (expired or
// unknown), so the user needs to log in again.
var errTokenRejected = errors.New("token rejected")

type notesResponse struct {
	Owner string   `json:"owner"`
	Notes []string `json:"notes"`
}

// callNotes calls the notes API with the token (GET to list, POST with a JSON
// body to add). a.oauth.Client adds "Authorization: Bearer <token>" to every
// request it sends. Both calls answer with the owner's notes.
func (a *app) callNotes(ctx context.Context, tok *oauth2.Token, method string, body []byte) (notesResponse, error) {
	var notes notesResponse
	if !tok.Valid() {
		return notes, errTokenRejected // expired: no point asking
	}
	req, err := http.NewRequestWithContext(ctx, method, a.notesURL+"/notes", bytes.NewReader(body))
	if err != nil {
		return notes, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.oauth.Client(ctx, tok).Do(req)
	if err != nil {
		return notes, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		err = json.NewDecoder(resp.Body).Decode(&notes)
		return notes, err
	case http.StatusUnauthorized:
		return notes, errTokenRejected
	default:
		return notes, fmt.Errorf("notes API returned %s", resp.Status)
	}
}
