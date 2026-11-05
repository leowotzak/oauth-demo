package main

import (
	"sync"
	"time"
)

// TokenRecord is what the server remembers about an access token it issued.
type TokenRecord struct {
	clientID  string
	userID    string // the user the client acts for; empty for client credentials
	scope     []string
	expiresAt time.Time
}

// TokenStore holds issued access tokens, keyed by the SHA-256 of the token.
// Requests run concurrently, so every access goes through the mutex.
type TokenStore struct {
	mu     sync.Mutex
	tokens map[string]*TokenRecord
}

func newTokenStore() *TokenStore {
	return &TokenStore{tokens: map[string]*TokenRecord{}}
}

// issue creates an opaque random access token, saves its record and returns it.
// userID is empty when no user is involved (client credentials).
func (s *TokenStore) issue(clientID, userID string, scope []string, ttl time.Duration) string {
	token := generateSecret()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[hashSecret(token)] = &TokenRecord{clientID, userID, scope, time.Now().Add(ttl)}
	return token
}

// lookup returns the record for a token, or false if it's unknown or expired.
func (s *TokenStore) lookup(token string) (*TokenRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.tokens[hashSecret(token)]
	if !ok || time.Now().After(rec.expiresAt) {
		return nil, false
	}
	return rec, true
}
