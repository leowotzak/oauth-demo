package main

import (
	"log"
	"net/http"
	"time"
)

// server holds everything the HTTP handlers need.
type server struct {
	clients  map[string]*ClientRecord
	tokens   *TokenStore
	tokenTTL time.Duration
}

func newServer() *server {
	return &server{
		clients:  newClientRegistry(),
		tokens:   newTokenStore(),
		tokenTTL: time.Hour,
	}
}

// routes maps URLs to handlers. "POST /token" means other methods get
// 405 Method Not Allowed automatically.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.handleToken)
	return mux
}

func main() {
	s := newServer()
	for id := range s.clients {
		log.Printf("registered client %s", id)
	}

	// Plain HTTP is fine on localhost for this tutorial. RFC 6749 requires
	// TLS for every endpoint in a real deployment.
	addr := "localhost:8080"
	log.Printf("auth server listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
