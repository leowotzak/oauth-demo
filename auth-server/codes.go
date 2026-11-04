package main

import (
	"sync"
	"time"
)

// AuthCode is what the server remembers about an authorization code. Everything
// here is checked again when the code is exchanged at /token, so a code is only
// useful to the right client, at the right redirect URI, with the right PKCE
// verifier, once, and only briefly.
type AuthCode struct {
	clientID    string
	userID      string // the user who logged in and consented
	redirectURI string // must be sent again, identically, at /token (§4.1.3)
	scope       []string
	challenge   string // PKCE code_challenge (S256), checked against the verifier
	expiresAt   time.Time
	used        bool // single use (§4.1.2); reuse suggests the code was stolen
}

// CodeStore holds issued authorization codes, keyed by the SHA-256 of the code.
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*AuthCode
}

func newCodeStore() *CodeStore {
	return &CodeStore{codes: map[string]*AuthCode{}}
}

// issue creates a random authorization code, saves its record and returns it.
func (s *CodeStore) issue(rec AuthCode, ttl time.Duration) string {
	code := generateSecret()
	rec.expiresAt = time.Now().Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[hashSecret(code)] = &rec
	return code
}
