package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Access tokens are JWTs (RFC 9068), signed with Ed25519 ("EdDSA", RFC 8037).
// Resource servers check them themselves with the public key published at
// /.well-known/jwks.json, so they never call the auth server per request.
//
// The trade-off: the server no longer stores tokens, so it can't revoke one.
// A token works until it expires, which is why tokenTTL is short.

const (
	issuer   = "http://localhost:8080" // "iss": who issued the token
	audience = "notes-api"             // "aud": the API tokens are for (the only one here)
	keyID    = "key-1"                 // "kid": which key signed it, so keys can be rotated later
)

// accessTokenClaims is the JWT payload. It's signed, not encrypted: anyone
// holding the token can read it, so nothing secret goes in here.
type accessTokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub,omitempty"` // the user; omitted for client credentials
	Audience string `json:"aud"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	ID       string `json:"jti"` // unique token ID
}

// loadSigningKey turns the base64url 32-byte seed from .env into a key pair.
func loadSigningKey(seed string) (ed25519.PrivateKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(seed)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("JWT_SIGNING_KEY must be %d bytes, base64url-encoded", ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// issueAccessToken builds and signs a JWT access token. userID is empty for
// client credentials, since no user is involved.
func (s *server) issueAccessToken(clientID, userID string, scope []string) string {
	now := time.Now()
	return signJWT(s.signingKey,
		map[string]string{"alg": "EdDSA", "typ": "at+jwt", "kid": keyID},
		accessTokenClaims{
			Issuer:   issuer,
			Subject:  userID,
			Audience: audience,
			ClientID: clientID,
			Scope:    strings.Join(scope, " "),
			IssuedAt: now.Unix(),
			Expires:  now.Add(s.tokenTTL).Unix(),
			ID:       generateSecret(),
		})
}

// signJWT produces header.payload.signature: each part base64url-encoded,
// and the signature computed over "header.payload" (RFC 7515).
func signJWT(key ed25519.PrivateKey, header, claims any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signingInput := b64(h) + "." + b64(c)
	return signingInput + "." + b64(ed25519.Sign(key, []byte(signingInput)))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// handleJWKS implements GET /.well-known/jwks.json: the public key resource
// servers use to check signatures (RFC 7517; Ed25519 keys per RFC 8037).
// It's public on purpose: a public key can verify tokens but not make them.
func (s *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   b64(s.signingKey.Public().(ed25519.PublicKey)),
			"kid": keyID,
			"alg": "EdDSA",
			"use": "sig",
		}},
	})
}
