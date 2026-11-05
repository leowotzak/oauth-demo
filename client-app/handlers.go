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
	s := a.sessionFor(w, r)
	a.mu.Lock()
	tok := s.token
	a.mu.Unlock()

	if tok == nil {
		render(w, http.StatusOK, page{})
		return
	}
	notes, err := a.listNotes(r.Context(), tok)
	if errors.Is(err, errTokenRejected) {
		a.setToken(s, nil)
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
// and PKCE verifier in the session, then sends the browser to the auth server.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	s := a.sessionFor(w, r)
	state := rand.Text()
	verifier := oauth2.GenerateVerifier()

	a.mu.Lock()
	s.state, s.verifier = state, verifier
	a.mu.Unlock()

	// AuthCodeURL builds /authorize?response_type=code&client_id&redirect_uri
	// &scope&state; S256ChallengeOption adds code_challenge=BASE64URL(SHA256(verifier))
	// and code_challenge_method=S256. Only the challenge goes through the browser.
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// handleCallback is where the auth server sends the browser back, with
// ?code=…&state=… or ?error=…&state=…
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	s := a.sessionFor(w, r)
	q := r.URL.Query()

	// state and verifier are single use: take them out of the session now,
	// whatever happens next.
	a.mu.Lock()
	state, verifier := s.state, s.verifier
	s.state, s.verifier = "", ""
	a.mu.Unlock()

	// 1. Only accept a response to a login this browser started (CSRF).
	//    Checked before anything else, including errors.
	if state == "" || q.Get("state") != state {
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
	tok, err := a.oauth.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		log.Printf("code exchange failed: %v", err)
		render(w, http.StatusBadGateway, page{Message: "Login failed: the authorization code couldn't be exchanged. Try logging in again."})
		return
	}

	// 4. Keep the token on the server; the browser only has its session cookie.
	a.setToken(s, tok)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleAddNote adds a note through the notes API with the stored token.
func (a *app) handleAddNote(w http.ResponseWriter, r *http.Request) {
	s := a.sessionFor(w, r)
	a.mu.Lock()
	tok := s.token
	a.mu.Unlock()
	if tok == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	err := a.addNote(r.Context(), tok, r.PostFormValue("text"))
	if errors.Is(err, errTokenRejected) {
		a.setToken(s, nil)
	} else if err != nil {
		log.Printf("adding note: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout forgets the token. (The token itself stays valid at the auth
// server until it expires; revoking it needs a /revoke endpoint.)
func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.setToken(a.sessionFor(w, r), nil)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) setToken(s *session, tok *oauth2.Token) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s.token = tok
}

// errTokenRejected means the notes API refused the token (expired or
// unknown), so the user needs to log in again.
var errTokenRejected = errors.New("token rejected")

type notesResponse struct {
	Owner string   `json:"owner"`
	Notes []string `json:"notes"`
}

// listNotes calls GET /notes. a.oauth.Client adds "Authorization: Bearer
// <token>" to every request it sends.
func (a *app) listNotes(ctx context.Context, tok *oauth2.Token) (notesResponse, error) {
	var notes notesResponse
	if !tok.Valid() {
		return notes, errTokenRejected
	}
	resp, err := a.oauth.Client(ctx, tok).Get(a.notesURL + "/notes")
	if err != nil {
		return notes, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return notes, errTokenRejected
	}
	if resp.StatusCode != http.StatusOK {
		return notes, fmt.Errorf("notes API returned %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&notes)
	return notes, err
}

// addNote calls POST /notes with the token.
func (a *app) addNote(ctx context.Context, tok *oauth2.Token, text string) error {
	if !tok.Valid() {
		return errTokenRejected
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := a.oauth.Client(ctx, tok).Post(a.notesURL+"/notes", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errTokenRejected
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("notes API returned %s", resp.Status)
	}
	return nil
}
