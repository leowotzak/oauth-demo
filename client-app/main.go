package main

import (
	"errors"
	"crypto/rand"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

// session is what client-app remembers about one browser. The browser only
// ever holds a random session ID in a cookie; everything here stays on the
// server, including the access token ("backend for frontend").
type session struct {
	state    string        // CSRF protection for /callback; single use
	verifier string        // PKCE code_verifier; never leaves this server
	token    *oauth2.Token // the access token, once logged in
}

// app is a web app that acts for users: client1 in the authorization code flow.
type app struct {
	oauth    *oauth2.Config
	notesURL string

	mu       sync.Mutex
	sessions map[string]*session // session ID (cookie value) → session
}

func newApp(clientID, clientSecret, redirectURL, authServerURL, notesURL string) *app {
	return &app{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"notes:read", "notes:write"},
			Endpoint: oauth2.Endpoint{
				AuthURL:   authServerURL + "/authorize",
				TokenURL:  authServerURL + "/token",
				AuthStyle: oauth2.AuthStyleInHeader, // HTTP Basic, as RFC 6749 §2.3.1 recommends
			},
		},
		notesURL: notesURL,
		sessions: map[string]*session{},
	}
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("GET /callback", a.handleCallback)
	mux.HandleFunc("POST /notes", a.handleAddNote)
	mux.HandleFunc("POST /logout", a.handleLogout)
	return mux
}

// sessionFor returns the browser's session, creating one (and its cookie) if
// it doesn't have one yet.
func (a *app) sessionFor(w http.ResponseWriter, r *http.Request) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, err := r.Cookie("session"); err == nil {
		if s, ok := a.sessions[c.Value]; ok {
			return s
		}
	}
	id := rand.Text()
	s := &session{}
	a.sessions[id] = s
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,                 // page scripts can't read it
		SameSite: http.SameSiteLaxMode, // sent on the redirect back from the auth server, not on cross-site POSTs
	})
	return s
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing environment variable %s (is it in .env, and are you running from the client-app folder?)", key)
	}
	return v
}

func main() {
	// A missing .env is normal in Docker, where Compose passes the settings
	// in as environment variables. Only a file that exists but can't be read
	// is worth reporting.
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("not loading .env: %v", err)
	}
	a := newApp(mustGetenv("CLIENT_ID"), mustGetenv("CLIENT_SECRET"), mustGetenv("REDIRECT_URL"),
		mustGetenv("AUTH_SERVER_URL"), mustGetenv("NOTES_API_URL"))

	// AUTH_SERVER_URL is where the user's browser goes (/authorize). The
	// /token request comes from this server instead, which may need a
	// different address, e.g. http://auth-server:8080 inside Docker Compose,
	// where "localhost" would mean this container.
	if v := os.Getenv("AUTH_SERVER_INTERNAL_URL"); v != "" {
		a.oauth.Endpoint.TokenURL = v + "/token"
	}

	addr := "localhost:9000"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v // e.g. 0.0.0.0:9000 in a container, so it's reachable from outside
	}
	log.Printf("client-app listening on http://%s (as %s)", addr, a.oauth.ClientID)
	log.Fatal(http.ListenAndServe(addr, a.routes()))
}
