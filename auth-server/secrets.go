package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// These helpers created the client secrets and their hashes, which are now
// stored in .env for ease of access while following this tutorial. The token
// store also uses them: generateSecret creates access tokens, and hashSecret
// hashes client secrets and tokens before they're stored or compared.
//
// TUTORIAL ONLY: keeping plaintext secrets in .env next to the server is
// insecure. In a real deployment the server would hold only the hashes, and
// each plaintext secret would be shown once to its client's owner, then
// never stored.

// generateSecret returns a new client secret or access token with 256 bits of randomness
// (RFC 6749 §10.10 requires at least 128, recommends at least 160).
// It is base64url-encoded without padding, so it only contains unreserved
// characters (A-Z a-z 0-9 - _) and never needs escaping in a Basic auth
// header or a form body.
func generateSecret() string {
	b := make([]byte, 32)
	rand.Read(b) // crypto/rand, never math/rand
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashSecret returns the hex-encoded SHA-256 of a secret. This is the value
// stored in the registry. A fast hash is fine here because the secret is
// long and random; slow hashes like bcrypt are for guessable human passwords.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
