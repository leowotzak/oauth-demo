package main

import (
	"crypto/ed25519"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

// server is the notes API: a resource server that accepts JWT access tokens
// issued by auth-server and checks each one locally with its public key.
type server struct {
	jwksURL    string // where auth-server publishes its public keys
	issuer     string // the "iss" tokens must have
	audience   string // the "aud" tokens must have: this API's name
	httpClient *http.Client

	keysMu sync.Mutex
	keys   map[string]ed25519.PublicKey // cached from the JWKS, by key ID

	mu    sync.Mutex
	notes map[string][]string // owner (user ID, or "client:<id>") → their notes
}

func newServer(jwksURL, issuer, audience string) *server {
	return &server{
		jwksURL:    jwksURL,
		issuer:     issuer,
		audience:   audience,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		notes: map[string][]string{
			"user-1": {"Buy milk"},                    // alice
			"user-2": {"Prepare for OAuth interview"}, // bob
		},
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
	s := newServer(mustGetenv("JWKS_URL"), mustGetenv("ISSUER"), mustGetenv("AUDIENCE"))

	addr := "localhost:8081"
	log.Printf("notes API listening on http://%s (keys from %s)", addr, s.jwksURL)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
