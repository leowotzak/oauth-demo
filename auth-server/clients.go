package main

import (
	"crypto/subtle"
	"log"
	"os"
)

// Each field answers a question the server will ask while handling a request.
type ClientRecord struct {
	// The unique identifier for the client. It's public and appears in URLs,
	// so it isn't a secret. Should be unique and stable, random strings or
	// readable slugs both work.
	id string

	// Lets you verify a confidential client. Store a hash, never
	// the plaintext
	secretHash string

	// List of grant_type values client may use at /token
	// Ex.) "authorization_code", "client_credentials", "refresh_token"
	allowedGrantTypes map[string]bool

	// Individual scope names this client may be granted. Each scope is a label
	// for a set of permissions. Scopes are case-sensitive (RFC 6749 §3.3).
	// Requests send them as one space-separated string; split it before
	// checking each name against this set.
	// Scopes limit the client, not the user.
	// Flat scopes: "read", "write", "admin"
	// Resource scopes: "notes:read", "notes:write", "metrics:read"
	allowedScopes map[string]bool

	// Scopes granted when a token request omits the scope parameter
	// (RFC 6749 §3.3: use a pre-defined default or fail). Should be a non-empty
	// subset of allowedScopes. Keep it narrower than allowedScopes so
	// powerful scopes must be asked for explicitly.
	defaultScopes []string
}

// knownGrantTypes are the grant_type values this server understands.
// /token returns unsupported_grant_type for anything else.
var knownGrantTypes = map[string]bool{
	"authorization_code": true,
	"client_credentials": true,
	"refresh_token":      true,
}

// createClientRecord builds a client's record. It doesn't validate its input;
// a production server would reject bad configuration here.
func createClientRecord(id string, secretHash string, allowedGrantTypes, allowedScopes, defaultScopes []string) *ClientRecord {
	grantTypes := make(map[string]bool)
	for _, gt := range allowedGrantTypes {
		grantTypes[gt] = true
	}

	scopes := make(map[string]bool)
	for _, s := range allowedScopes {
		scopes[s] = true
	}

	return &ClientRecord{
		id:                id,
		secretHash:        secretHash,
		allowedGrantTypes: grantTypes,
		allowedScopes:     scopes,
		defaultScopes:     defaultScopes,
	}
}

// mustGetenv returns the value of an environment variable, or stops the
// server if it's missing. A client with an empty secret hash must never be
// registered, so failing at startup is safer than continuing.
func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing environment variable %s (did you `set -a; source .env; set +a`?)", key)
	}
	return v
}

// newClientRegistry builds the registry from the secret hashes in the
// environment. It's separate from main so tests can build the same registry.
func newClientRegistry() map[string]*ClientRecord {
	client1 := createClientRecord("client1", mustGetenv("SECRET1_HASH"), []string{"authorization_code"}, []string{"notes:read", "notes:write"}, []string{"notes:read"})
	client2 := createClientRecord("client2", mustGetenv("SECRET2_HASH"), []string{"client_credentials"}, []string{"notes:read"}, []string{"notes:read"})
	// Machine client with several scopes across two resources, for testing
	// multi-scope requests and partially-allowed scope lists.
	client3 := createClientRecord("client3", mustGetenv("SECRET3_HASH"), []string{"client_credentials"}, []string{"notes:read", "notes:write", "metrics:read"}, []string{"notes:read"})
	// warning: if clientX, and clientY have the same id, one will overwrite the other in the map
	clientRegistry := map[string]*ClientRecord{
		client1.id: client1,
		client2.id: client2,
		client3.id: client3,
	}
	return clientRegistry
}

func authenticateClient(clientRegistry map[string]*ClientRecord, id, secret string) (*ClientRecord, bool) {
	presented := hashSecret(secret)
	client := clientRegistry[id]
	if client == nil {
		subtle.ConstantTimeCompare([]byte(presented), []byte(hashSecret("dummy")))
		return nil, false
	}

	match := subtle.ConstantTimeCompare([]byte(presented), []byte(client.secretHash)) == 1
	if match {
		return client, true
	}

	return nil, false
}
