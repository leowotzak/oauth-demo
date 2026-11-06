package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	testIssuer   = "http://localhost:8080"
	testAudience = "notes-api"
)

// testKeys is a key pair standing in for auth-server's signing key.
var testPublic, testPrivate, _ = ed25519.GenerateKey(nil)

// fakeAuthServer publishes testPublic as the JWKS, the way auth-server does.
func fakeAuthServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "kid": "key-1", "alg": "EdDSA",
			"x": base64.RawURLEncoding.EncodeToString(testPublic),
		}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testRedis starts an in-process fake Redis for one test.
func testRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	mr := miniredis.RunT(t)
	return mr, redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// newTestServer is a notes API with its own fake Redis, seeded like main does.
func newTestServer(t *testing.T) *server {
	_, rdb := testRedis(t)
	s := newServer(fakeAuthServer(t).URL, testIssuer, testAudience, rdb)
	if err := s.seedNotes(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// sign builds a JWT from a header and claims, signed with key.
func sign(key ed25519.PrivateKey, header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := enc(h) + "." + enc(c)
	return input + "." + enc(ed25519.Sign(key, []byte(input)))
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func goodHeader() map[string]any {
	return map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "key-1"}
}

// token makes a valid access token; change() can alter its header or claims.
func token(sub, clientID, scope string, change func(h, c map[string]any)) string {
	h := goodHeader()
	c := map[string]any{
		"iss": testIssuer, "aud": testAudience, "client_id": clientID, "scope": scope,
		"iat": time.Now().Unix(), "exp": time.Now().Add(15 * time.Minute).Unix(), "jti": "x",
	}
	if sub != "" {
		c["sub"] = sub
	}
	if change != nil {
		change(h, c)
	}
	return sign(testPrivate, h, c)
}

func call(s *server, method, tok, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/notes", strings.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestValidTokens(t *testing.T) {
	s := newTestServer(t)
	read := token("", "client2", "notes:read", nil)
	write := token("", "client3", "notes:read notes:write", nil)

	cases := []struct {
		name, method, tok, body string
		wantStatus              int
		wantChallenge           string
	}{
		{"no token", "GET", "", "", 401, `Bearer realm="notes"`},
		{"read token can read", "GET", read, "", 200, ""},
		{"read token cannot write", "POST", read, `{"text":"hi"}`, 403, `error="insufficient_scope", scope="notes:write"`},
		{"write token can write", "POST", write, `{"text":"hi"}`, 201, ""},
		{"write token, bad body", "POST", write, `nope`, 400, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := call(s, c.method, c.tok, c.body)
			if w.Code != c.wantStatus {
				t.Fatalf("status %d, want %d (body %s)", w.Code, c.wantStatus, w.Body)
			}
			if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, c.wantChallenge) {
				t.Errorf("WWW-Authenticate = %q, want it to contain %q", got, c.wantChallenge)
			}
		})
	}
}

// Every way a token can be wrong must give 401 invalid_token.
func TestRejectedTokens(t *testing.T) {
	s := newTestServer(t)
	_, otherKey, _ := ed25519.GenerateKey(nil)
	valid := token("user-1", "client1", "notes:read", nil)
	parts := strings.Split(valid, ".")

	// Widen the scope in the payload but keep the original signature.
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	widened := strings.Replace(string(payload), `"scope":"notes:read"`, `"scope":"notes:read notes:write"`, 1)

	noneHeader, _ := json.Marshal(map[string]string{"alg": "none", "typ": "at+jwt", "kid": "key-1"})

	cases := map[string]string{
		"not a JWT":                "made-up",
		"signed by another key":    sign(otherKey, goodHeader(), map[string]any{"iss": testIssuer, "aud": testAudience, "scope": "notes:read", "exp": time.Now().Add(time.Hour).Unix()}),
		"tampered payload":         parts[0] + "." + enc([]byte(widened)) + "." + parts[2],
		`alg "none", no signature`: enc(noneHeader) + "." + parts[1] + ".",
		"alg HS256":                token("", "client2", "notes:read", func(h, c map[string]any) { h["alg"] = "HS256" }),
		"not an access token":      token("", "client2", "notes:read", func(h, c map[string]any) { h["typ"] = "JWT" }),
		"unknown key ID":           token("", "client2", "notes:read", func(h, c map[string]any) { h["kid"] = "key-9" }),
		"wrong issuer":             token("", "client2", "notes:read", func(h, c map[string]any) { c["iss"] = "https://evil.example" }),
		"wrong audience":           token("", "client2", "notes:read", func(h, c map[string]any) { c["aud"] = "billing-api" }),
		"expired":                  token("", "client2", "notes:read", func(h, c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			w := call(s, "GET", tok, "")
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
				t.Errorf("status %d, WWW-Authenticate %q; want 401 invalid_token", w.Code, w.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestExpiryAllowsSmallClockSkew(t *testing.T) {
	s := newTestServer(t)
	justExpired := token("", "client2", "notes:read", func(h, c map[string]any) { c["exp"] = time.Now().Add(-5 * time.Second).Unix() })
	if w := call(s, "GET", justExpired, ""); w.Code != http.StatusOK {
		t.Errorf("status %d, want 200 within the clock skew allowance", w.Code)
	}
}

// Keys are fetched once, not on every request.
func TestKeysAreCached(t *testing.T) {
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "kid": "key-1", "x": enc(testPublic),
		}}})
	}))
	t.Cleanup(srv.Close)
	_, rdb := testRedis(t)
	s := newServer(srv.URL, testIssuer, testAudience, rdb)

	for range 3 {
		call(s, "GET", token("", "client2", "notes:read", nil), "")
	}
	if fetches != 1 {
		t.Errorf("JWKS fetched %d times, want 1", fetches)
	}
}

func TestAuthServerDown(t *testing.T) {
	// The keys can't be fetched, so no token can be checked: fail closed.
	_, rdb := testRedis(t)
	s := newServer("http://127.0.0.1:1/.well-known/jwks.json", testIssuer, testAudience, rdb)
	if w := call(s, "GET", token("", "client2", "notes:read", nil), ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", w.Code)
	}
}

// notesFor calls GET /notes with a token and decodes the response.
func notesFor(t *testing.T, s *server, tok string) notesResponse {
	t.Helper()
	w := call(s, "GET", tok, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /notes: status %d (%s)", w.Code, w.Body)
	}
	var resp notesResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp
}

// alice and bob use the same client (client1), but each token acts for a
// different user, so each sees only their own notes.
func TestNotesArePerUser(t *testing.T) {
	s := newTestServer(t)
	alice := token("user-1", "client1", "notes:read notes:write", nil)
	bob := token("user-2", "client1", "notes:read notes:write", nil)

	if got := notesFor(t, s, alice); got.Owner != "user-1" || !slices.Equal(got.Notes, []string{"Buy milk"}) {
		t.Errorf("alice got %+v", got)
	}
	if w := call(s, "POST", bob, `{"text":"bob's secret"}`); w.Code != http.StatusCreated {
		t.Fatalf("bob POST: status %d", w.Code)
	}
	if got := notesFor(t, s, bob); got.Owner != "user-2" || !slices.Contains(got.Notes, "bob's secret") {
		t.Errorf("bob got %+v", got)
	}
	if slices.Contains(notesFor(t, s, alice).Notes, "bob's secret") {
		t.Error("alice can see bob's note")
	}
}

// Client credentials tokens have no user, so their notes belong to the
// client itself, separate from every user's.
func TestNotesForClientWithoutUser(t *testing.T) {
	s := newTestServer(t)
	got := notesFor(t, s, token("", "client2", "notes:read", nil))
	if got.Owner != "client:client2" || got.Notes == nil || len(got.Notes) != 0 {
		t.Errorf("got %+v, want owner client:client2 with an empty list", got)
	}
}

// A revoked token still has a valid signature, so only the deny list in
// Redis stops it.
func TestRevokedTokenIsRejected(t *testing.T) {
	mr, rdb := testRedis(t)
	s := newServer(fakeAuthServer(t).URL, testIssuer, testAudience, rdb)
	tok := token("", "client2", "notes:read", func(h, c map[string]any) { c["jti"] = "revoked-one" })

	if w := call(s, "GET", tok, ""); w.Code != http.StatusOK {
		t.Fatalf("before revoking: status %d", w.Code)
	}
	mr.Set("revoked:revoked-one", "1") // what the auth server's /revoke does
	w := call(s, "GET", tok, "")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "revoked") {
		t.Errorf("after revoking: status %d, body %q; want 401 revoked", w.Code, w.Body)
	}
}

// Without Redis, revocation can't be checked: fail closed, even for a token
// with a good signature.
func TestRedisDown(t *testing.T) {
	s := newServer(fakeAuthServer(t).URL, testIssuer, testAudience,
		redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1}))
	if w := call(s, "GET", token("", "client2", "notes:read", nil), ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", w.Code)
	}
}

// Notes live in Redis, so they survive a restart, and seeding again doesn't
// duplicate them.
func TestNotesSurviveRestart(t *testing.T) {
	_, rdb := testRedis(t)
	auth := fakeAuthServer(t).URL
	alice := token("user-1", "client1", "notes:read notes:write", nil)

	first := newServer(auth, testIssuer, testAudience, rdb)
	first.seedNotes(context.Background())
	call(first, "POST", alice, `{"text":"remember me"}`)

	restarted := newServer(auth, testIssuer, testAudience, rdb)
	restarted.seedNotes(context.Background())
	if got := notesFor(t, restarted, alice).Notes; !slices.Equal(got, []string{"Buy milk", "remember me"}) {
		t.Errorf("after restart: %v", got)
	}
}
