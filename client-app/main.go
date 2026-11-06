package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

// app is a web app that acts for users: client1 in the authorization code flow.
type app struct {
	oauth    *oauth2.Config
	notesURL string
	rdb      *redis.Client // sessions (see sessions.go)
}

func newApp(clientID, clientSecret, redirectURL, authServerURL, notesURL string, rdb *redis.Client) *app {
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
		rdb:      rdb,
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
	opts, err := redis.ParseURL(mustGetenv("REDIS_URL"))
	if err != nil {
		log.Fatalf("REDIS_URL: %v", err)
	}
	a := newApp(mustGetenv("CLIENT_ID"), mustGetenv("CLIENT_SECRET"), mustGetenv("REDIRECT_URL"),
		mustGetenv("AUTH_SERVER_URL"), mustGetenv("NOTES_API_URL"), redis.NewClient(opts))
	if err := a.rdb.Ping(context.Background()).Err(); err != nil {
		log.Printf("warning: can't reach Redis yet (%v); logins will fail until it's up", err)
	}

	// AUTH_SERVER_URL is where the user's browser goes (/authorize). The
	// /token and /revoke requests come from this server instead, which may need a
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
