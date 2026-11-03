package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
)

// ClientRecord is what the server knows about a registered client.
type ClientRecord struct {
	id            string   // public identifier, sent with every request
	secretHash    string   // SHA-256 of the client secret; never store the plaintext
	grantTypes    []string // grant_type values this client may use
	scopes        []string // scopes this client may be granted (case-sensitive)
	defaultScopes []string // granted when a request omits scope (RFC 6749 §3.3)
}

// mustGetenv returns an environment variable, or stops the server if it's missing.
func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing environment variable %s (is it in .env, and are you running from the auth-server folder?)", key)
	}
	return v
}

// newClientRegistry returns the registered clients, keyed by ID.
// The secret hashes come from .env.
func newClientRegistry() map[string]*ClientRecord {
	return map[string]*ClientRecord{
		// Not allowed client_credentials: tests unauthorized_client.
		"client1": {
			id:            "client1",
			secretHash:    mustGetenv("SECRET1_HASH"),
			grantTypes:    []string{"authorization_code"},
			scopes:        []string{"notes:read", "notes:write"},
			defaultScopes: []string{"notes:read"},
		},
		// The basic client_credentials client.
		"client2": {
			id:            "client2",
			secretHash:    mustGetenv("SECRET2_HASH"),
			grantTypes:    []string{"client_credentials"},
			scopes:        []string{"notes:read"},
			defaultScopes: []string{"notes:read"},
		},
		// Several scopes across two resources; defaults narrower than allowed.
		"client3": {
			id:            "client3",
			secretHash:    mustGetenv("SECRET3_HASH"),
			grantTypes:    []string{"client_credentials"},
			scopes:        []string{"notes:read", "notes:write", "metrics:read"},
			defaultScopes: []string{"notes:read"},
		},
	}
}

// clientCredentials reads the client ID and secret from HTTP Basic auth, or
// from client_id/client_secret in the body (RFC 6749 §2.3.1).
func clientCredentials(r *http.Request) (id, secret string) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	return id, secret
}

// authenticateClient checks a client ID and secret against the registry.
// It compares hashes, never plaintext, in constant time.
func authenticateClient(clients map[string]*ClientRecord, id, secret string) (*ClientRecord, bool) {
	client, ok := clients[id]
	if !ok || subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(client.secretHash)) != 1 {
		return nil, false
	}
	return client, true
}
