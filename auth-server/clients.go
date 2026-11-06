package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
)

// ClientRecord is what the server knows about a registered client.
type ClientRecord struct {
	id            string   // public identifier, sent with every request
	secretHash    string   // SHA-256 of the client secret; never store the plaintext
	grantTypes    []string // grant_type values this client may use
	scopes        []string // scopes this client may be granted (case-sensitive)
	defaultScopes []string // granted when a request omits scope (RFC 6749 §3.3)
	redirectURIs  []string // where /authorize may send codes (authorization code flow)
}

// allowsRedirect reports whether a redirect URI is registered for this client.
// Exact string match only: the code is the user's grant, and any looser
// matching (prefixes, patterns) lets attackers send it somewhere they control.
func (c *ClientRecord) allowsRedirect(uri string) bool {
	return slices.Contains(c.redirectURIs, uri)
}

// resolveScope works out which scopes to grant (RFC 6749 §3.3): the client's
// defaults if raw is empty, otherwise every requested scope, all of which must
// be allowed. If one isn't, it's returned as disallowed and nothing is granted.
// Used by both /token and /authorize.
func resolveScope(c *ClientRecord, raw string) (scope []string, disallowed string) {
	if raw == "" {
		return c.defaultScopes, ""
	}
	scope = strings.Fields(raw)
	for _, sc := range scope {
		if !slices.Contains(c.scopes, sc) {
			return nil, sc
		}
	}
	return scope, ""
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
		// A web app that acts for users (authorization code flow). Not allowed
		// client_credentials: tests unauthorized_client.
		"client1": {
			id:            "client1",
			secretHash:    mustGetenv("SECRET1_HASH"),
			grantTypes:    []string{"authorization_code"},
			scopes:        []string{"notes:read", "notes:write"},
			defaultScopes: []string{"notes:read"},
			redirectURIs:  []string{"http://localhost:9000/callback"},
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

// authenticateCaller parses the form body and authenticates the client making
// the request, from HTTP Basic auth or client_id/client_secret in the body
// (RFC 6749 §2.3.1). On failure it has already written invalid_client (401).
func (s *server) authenticateCaller(w http.ResponseWriter, r *http.Request) (*ClientRecord, bool) {
	r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	client, ok := authenticateClient(s.clients, id, secret)
	if !ok {
		writeError(w, http.StatusUnauthorized, errInvalidClient, "client authentication failed")
	}
	return client, ok
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
