package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

// server holds everything the HTTP handlers need.
type server struct {
	clients    map[string]*ClientRecord
	users      map[string]*User
	signingKey ed25519.PrivateKey // signs JWT access tokens
	tokenTTL   time.Duration      // short, because a JWT can't be revoked before it expires
	rdb        *redis.Client      // authorization codes and revoked token IDs
	codes      *CodeStore
	codeTTL    time.Duration // authorization codes: short-lived (§4.1.2 says at most 10 minutes)
}

func newServer() *server {
	key, err := loadSigningKey(mustGetenv("JWT_SIGNING_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	opts, err := redis.ParseURL(mustGetenv("REDIS_URL"))
	if err != nil {
		log.Fatalf("REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opts)
	return &server{
		clients:    newClientRegistry(),
		users:      newUserRegistry(),
		signingKey: key,
		tokenTTL:   15 * time.Minute,
		rdb:        rdb,
		codes:      &CodeStore{rdb},
		codeTTL:    time.Minute,
	}
}

// routes maps URLs to handlers. "POST /token" means other methods get
// 405 Method Not Allowed automatically.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /revoke", s.handleRevoke)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /authorize", s.handleAuthorizeSubmit)
	return mux
}

func main() {
	// Load the client secrets from .env. Variables already set win.
	// A missing .env is normal in Docker, where Compose passes the settings
	// in as environment variables. Only a file that exists but can't be read
	// is worth reporting.
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("not loading .env: %v", err)
	}

	s := newServer()
	if err := s.rdb.Ping(context.Background()).Err(); err != nil {
		log.Printf("warning: can't reach Redis yet (%v); logins will fail until it's up", err)
	}

	// Plain HTTP for the tutorial; RFC 6749 requires TLS in real deployments.
	addr := "localhost:8080"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v // e.g. 0.0.0.0:8080 in a container, so it's reachable from outside
	}
	log.Printf("auth server listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
