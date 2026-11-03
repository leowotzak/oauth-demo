package main

import (
	"sync"
	"time"
)

// TokenRecord is what the server remembers about an access token it issued.
// It answers "is this token valid, and what does it allow?"
type TokenRecord struct {
	// The client the token was issued to. Store the ID, not the ClientRecord,
	// so lookups always see the client's current settings.
	clientID string

	// The scopes actually granted, which may differ from what was requested.
	scope []string

	// When the token stops working. Reported to the client as expires_in.
	expiresAt time.Time
}

// TokenStore holds issued access tokens. Unlike the client registry, it's
// written on every token request, and Go's HTTP server handles requests
// concurrently, so every access goes through the mutex.
type TokenStore struct {
	mu sync.Mutex

	// Keyed by the SHA-256 hash of the token, never the token itself, so a
	// dump of the store doesn't hand out working tokens.
	tokens map[string]*TokenRecord
}

func newTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]*TokenRecord)}
}

// issue creates an opaque access token for a client, saves its record and
// returns the token. The token is 256 bits of randomness (RFC 6749 §10.10).
// ttl is a parameter so tests can create already-expired tokens.
func (s *TokenStore) issue(clientID string, scope []string, ttl time.Duration) (string, *TokenRecord) {
	token := generateSecret()
	rec := &TokenRecord{
		clientID:  clientID,
		scope:     scope,
		expiresAt: time.Now().Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[hashSecret(token)] = rec
	return token, rec
}

// lookup returns the record for a token. A token that was never issued and
// a token that has expired both fail the same way.
func (s *TokenStore) lookup(token string) (*TokenRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.tokens[hashSecret(token)]
	if !ok || time.Now().After(rec.expiresAt) {
		return nil, false
	}
	return rec, true
}
