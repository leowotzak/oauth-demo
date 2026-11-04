package main

import (
	"log"
	"net/http"
	"time"

	"github.com/joho/godotenv"
)

// server holds everything the HTTP handlers need.
type server struct {
	clients  map[string]*ClientRecord
	users    map[string]*User
	tokens   *TokenStore
	tokenTTL time.Duration
	codes    *CodeStore
	codeTTL  time.Duration // authorization codes: short-lived (§4.1.2 says at most 10 minutes)
}

func newServer() *server {
	return &server{
		clients:  newClientRegistry(),
		users:    newUserRegistry(),
		tokens:   newTokenStore(),
		tokenTTL: time.Hour,
		codes:    newCodeStore(),
		codeTTL:  time.Minute,
	}
}

// routes maps URLs to handlers. "POST /token" means other methods get
// 405 Method Not Allowed automatically.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /introspect", s.handleIntrospect)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /authorize", s.handleAuthorizeSubmit)
	return mux
}

func main() {
	// Load the client secrets from .env. Variables already set win.
	if err := godotenv.Load(); err != nil {
		log.Printf("not loading .env: %v", err)
	}

	s := newServer()
	for id := range s.clients {
		log.Printf("registered client %s", id)
	}

	// Plain HTTP for the tutorial; RFC 6749 requires TLS in real deployments.
	addr := "localhost:8080"
	log.Printf("auth server listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
