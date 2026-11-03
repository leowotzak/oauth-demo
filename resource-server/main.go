package main

import (
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

// server is the notes API: a resource server that accepts access tokens
// issued by auth-server and checks each one by calling its /introspect.
type server struct {
	introspectURL string
	clientID      string // this server's own credentials for /introspect
	clientSecret  string
	httpClient    *http.Client

	mu    sync.Mutex
	notes []string
}

func newServer(introspectURL, clientID, clientSecret string) *server {
	return &server{
		introspectURL: introspectURL,
		clientID:      clientID,
		clientSecret:  clientSecret,
		httpClient:    &http.Client{Timeout: 5 * time.Second},
		notes:         []string{"Buy milk", "Prepare for OAuth interview"},
	}
}

// routes protects each endpoint with the scope it needs.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /notes", s.requireScope("notes:read", s.handleListNotes))
	mux.HandleFunc("POST /notes", s.requireScope("notes:write", s.handleAddNote))
	return mux
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing environment variable %s (is it in .env, and are you running from the resource-server folder?)", key)
	}
	return v
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("not loading .env: %v", err)
	}
	s := newServer(mustGetenv("INTROSPECT_URL"), mustGetenv("NOTES_API_CLIENT_ID"), mustGetenv("NOTES_API_SECRET"))

	addr := "localhost:8081"
	log.Printf("notes API listening on http://%s (checking tokens at %s)", addr, s.introspectURL)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
