package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
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

	// Redis holds the notes ("notes:<owner>" lists) and the auth server's list
	// of revoked token IDs ("revoked:<jti>").
	rdb *redis.Client
}

func newServer(jwksURL, issuer, audience string, rdb *redis.Client) *server {
	return &server{
		jwksURL:    jwksURL,
		issuer:     issuer,
		audience:   audience,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		rdb:        rdb,
	}
}

// seedNotes gives alice and bob a starting note, unless they already have
// notes (Redis keeps them across restarts).
func (s *server) seedNotes(ctx context.Context) error {
	for owner, note := range map[string]string{
		"user-1": "Buy milk",                    // alice
		"user-2": "Prepare for OAuth interview", // bob
	} {
		n, err := s.rdb.LLen(ctx, notesKey(owner)).Result()
		if err != nil {
			return err
		}
		if n == 0 {
			if err := s.rdb.RPush(ctx, notesKey(owner), note).Err(); err != nil {
				return err
			}
		}
	}
	return nil
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
	s := newServer(mustGetenv("JWKS_URL"), mustGetenv("ISSUER"), mustGetenv("AUDIENCE"), redis.NewClient(opts))
	if err := s.seedNotes(context.Background()); err != nil {
		log.Printf("warning: can't reach Redis yet (%v); requests will fail until it's up", err)
	}

	addr := "localhost:8081"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v // e.g. 0.0.0.0:8081 in a container, so it's reachable from outside
	}
	log.Printf("notes API listening on http://%s (keys from %s)", addr, s.jwksURL)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
