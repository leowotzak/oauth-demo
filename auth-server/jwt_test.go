package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// verifyTestToken checks a JWT the way a resource server would (header,
// signature) and returns its claims.
func verifyTestToken(t *testing.T, s *server, token string) accessTokenClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	var header map[string]string
	decodePart(t, parts[0], &header)
	if header["alg"] != "EdDSA" || header["typ"] != "at+jwt" || header["kid"] != keyID {
		t.Errorf("header = %v", header)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(s.signingKey.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signature doesn't verify")
	}
	var claims accessTokenClaims
	decodePart(t, parts[1], &claims)
	return claims
}

func decodePart(t *testing.T, part string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil || json.Unmarshal(b, v) != nil {
		t.Fatalf("bad JWT part %q", part)
	}
}

func TestAccessTokenClaims(t *testing.T) {
	s := newServer()
	token := s.issueAccessToken("client1", "user-1", []string{"notes:read", "notes:write"})
	c := verifyTestToken(t, s, token)

	if c.Issuer != issuer || c.Audience != audience || c.ClientID != "client1" || c.Subject != "user-1" || c.Scope != "notes:read notes:write" {
		t.Errorf("claims = %+v", c)
	}
	if c.Expires-c.IssuedAt != 15*60 {
		t.Errorf("lifetime = %ds, want 900", c.Expires-c.IssuedAt)
	}
	if other := verifyTestToken(t, s, s.issueAccessToken("client1", "user-1", nil)); c.ID == "" || other.ID == c.ID {
		t.Error("jti missing or repeated")
	}
}

func TestClientCredentialsTokenHasNoSub(t *testing.T) {
	s := newServer()
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(s.issueAccessToken("client2", "", []string{"notes:read"}), ".")[1])
	if strings.Contains(string(payload), `"sub"`) {
		t.Errorf("client credentials token has a sub: %s", payload)
	}
}

// Anyone can read and edit the payload, but not re-sign it.
func TestTamperedTokenFailsVerification(t *testing.T) {
	s := newServer()
	parts := strings.Split(s.issueAccessToken("client2", "", []string{"notes:read"}), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	widened := strings.Replace(string(payload), `"scope":"notes:read"`, `"scope":"notes:read notes:write"`, 1)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(widened))

	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if ed25519.Verify(s.signingKey.Public().(ed25519.PublicKey), []byte(tampered), sig) {
		t.Error("signature still verifies after widening the scope")
	}
}

func TestJWKSPublishesThePublicKey(t *testing.T) {
	s := newServer()
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if w.Code != http.StatusOK || len(jwks.Keys) != 1 {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	k := jwks.Keys[0]
	x, _ := base64.RawURLEncoding.DecodeString(k["x"])
	if k["kty"] != "OKP" || k["crv"] != "Ed25519" || k["alg"] != "EdDSA" || k["kid"] != keyID ||
		!ed25519.PublicKey(x).Equal(s.signingKey.Public()) {
		t.Errorf("key = %v", k)
	}
	if strings.Contains(w.Body.String(), `"d"`) {
		t.Error("JWKS contains private key material")
	}
}

func TestLoadSigningKeyRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "not base64!", base64.RawURLEncoding.EncodeToString([]byte("too short"))} {
		if _, err := loadSigningKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
