package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// generateSecret returns 256 random bits, base64url-encoded. Used for client
// secrets and access tokens (RFC 6749 §10.10 requires at least 128 bits).
func generateSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashSecret returns the hex SHA-256 of a secret or token. A fast hash is fine
// because the input is long and random; bcrypt is for human passwords.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
