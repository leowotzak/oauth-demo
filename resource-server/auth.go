package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
)

// claims are the parts of a JWT access token (RFC 9068) this service uses.
type claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"` // the user the token acts for; empty for client credentials
	Audience string `json:"aud"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	Expires  int64  `json:"exp"`
}

// owner is whose notes a token gives access to: the user it acts for, or,
// for client credentials tokens (no user), the client itself.
func (c claims) owner() string {
	if c.Subject != "" {
		return c.Subject
	}
	return "client:" + c.ClientID
}

// ownerKey stores the token's owner in the request context, so handlers know
// whose notes to use without touching tokens themselves.
type ownerKey struct{}

func ownerFrom(r *http.Request) string {
	return r.Context().Value(ownerKey{}).(string)
}

// clockSkew allows for small differences between this server's clock and
// the auth server's when checking expiry.
const clockSkew = 30 * time.Second

var (
	errInvalidToken    = errors.New("invalid token")            // → 401
	errKeysUnavailable = errors.New("signing keys unavailable") // → 503: can't check anything
)

func invalid(reason string) error { return fmt.Errorf("%w: %s", errInvalidToken, reason) }

// verify checks a JWT access token entirely locally and returns its claims.
// The order matters: decide how to verify from this server's own rules, check
// the signature, and only then trust anything the payload says.
func (s *server) verify(token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, invalid("not a JWT")
	}

	// 1. Header. Allow exactly one algorithm. Letting the token choose is how
	//    "alg": "none" and algorithm confusion attacks get in.
	var header struct{ Alg, Typ, Kid string }
	if decodeSegment(parts[0], &header) != nil {
		return claims{}, invalid("malformed header")
	}
	if header.Alg != "EdDSA" {
		return claims{}, invalid("algorithm not allowed")
	}
	if header.Typ != "at+jwt" {
		return claims{}, invalid("not an access token")
	}

	// 2. Signature, with the auth server's public key for this kid.
	key, err := s.keyFor(header.Kid)
	if err != nil {
		return claims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return claims{}, invalid("bad signature")
	}

	// 3. Claims: now that the signature checks out, they can be trusted.
	var c claims
	if decodeSegment(parts[1], &c) != nil {
		return claims{}, invalid("malformed claims")
	}
	if c.Issuer != s.issuer {
		return claims{}, invalid("wrong issuer")
	}
	if c.Audience != s.audience {
		return claims{}, invalid("token is for a different API")
	}
	if time.Now().After(time.Unix(c.Expires, 0).Add(clockSkew)) {
		return claims{}, invalid("expired")
	}
	return c, nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// keyFor returns the auth server's public key with this ID. Keys are fetched
// from its JWKS on first use, and again whenever a token names a key that
// isn't cached (for example after the auth server rotates keys).
func (s *server) keyFor(kid string) (ed25519.PublicKey, error) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if k, ok := s.keys[kid]; ok {
		return k, nil
	}
	keys, err := s.fetchKeys()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKeysUnavailable, err)
	}
	s.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, invalid("unknown signing key")
}

// fetchKeys downloads the auth server's JWKS (RFC 7517) and keeps its
// Ed25519 keys (RFC 8037), by key ID.
func (s *server) fetchKeys() (map[string]ed25519.PublicKey, error) {
	resp, err := s.httpClient.Get(s.jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned %s", resp.Status)
	}
	var jwks struct {
		Keys []struct{ Kty, Crv, X, Kid string } `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range jwks.Keys {
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if k.Kty == "OKP" && k.Crv == "Ed25519" && err == nil && len(x) == ed25519.PublicKeySize {
			keys[k.Kid] = ed25519.PublicKey(x)
		}
	}
	return keys, nil
}

// requireScope wraps a handler so it only runs for requests carrying a valid
// JWT access token with the given scope (RFC 6750).
//
//	no token          → 401, WWW-Authenticate: Bearer realm="notes"
//	invalid token     → 401, … error="invalid_token"
//	missing the scope → 403, … error="insufficient_scope", scope="…"
func (s *server) requireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Read the token from "Authorization: Bearer <token>" (§2.1).
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			bearerError(w, http.StatusUnauthorized, `Bearer realm="notes"`, "missing bearer token")
			return
		}

		// 2. Check it locally: signature, issuer, audience, expiry.
		c, err := s.verify(token)
		if errors.Is(err, errKeysUnavailable) {
			log.Printf("can't check tokens: %v", err)
			http.Error(w, "cannot check token right now", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			bearerError(w, http.StatusUnauthorized, `Bearer realm="notes", error="invalid_token"`, err.Error())
			return
		}

		// 3. Check it carries the scope this endpoint needs.
		if !slices.Contains(strings.Fields(c.Scope), scope) {
			bearerError(w, http.StatusForbidden, `Bearer realm="notes", error="insufficient_scope", scope="`+scope+`"`, "token lacks scope "+scope)
			return
		}

		// 4. Pass on whose data this request is about.
		next(w, r.WithContext(context.WithValue(r.Context(), ownerKey{}, c.owner())))
	}
}

// bearerError sends an RFC 6750 §3 error. The error code goes in the
// WWW-Authenticate header (the "challenge"); the plain-text body is just for
// people reading curl output.
func bearerError(w http.ResponseWriter, status int, challenge, message string) {
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, message, status)
}
