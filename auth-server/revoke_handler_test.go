package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func postRevoke(s *server, id, secret, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		r.SetBasicAuth(id, secret)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func jtiOf(t *testing.T, s *server, token string) string {
	t.Helper()
	claims, ok := s.parseAccessToken(token)
	if !ok {
		t.Fatal("not one of our tokens")
	}
	return claims.ID
}

func TestRevokeOwnToken(t *testing.T) {
	s := newServer()
	token := s.issueAccessToken("client2", "", []string{"notes:read"})

	w := postRevoke(s, "client2", os.Getenv("SECRET2"), url.Values{"token": {token}}.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	key := revokedKey(jtiOf(t, s, token))
	if !testRedis.Exists(key) {
		t.Fatal("token ID not on the deny list")
	}
	// The entry only needs to outlive the token itself.
	if ttl := testRedis.TTL(key); ttl <= 0 || ttl > 15*time.Minute {
		t.Errorf("deny list entry expires in %v, want within the token's 15 minutes", ttl)
	}
}

func TestRevokeIgnoresOtherClientsTokens(t *testing.T) {
	s := newServer()
	token := s.issueAccessToken("client3", "", []string{"notes:read"})

	// client2 authenticates fine, but the token belongs to client3.
	w := postRevoke(s, "client2", os.Getenv("SECRET2"), url.Values{"token": {token}}.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if testRedis.Exists(revokedKey(jtiOf(t, s, token))) {
		t.Error("a client revoked another client's token")
	}
}

// Invalid tokens need no action and still get 200, so callers learn nothing.
func TestRevokeInvalidTokenStillSucceeds(t *testing.T) {
	s := newServer()
	testRedis.FlushAll()
	for _, token := range []string{"not-a-token", "a.b.c"} {
		if w := postRevoke(s, "client2", os.Getenv("SECRET2"), "token="+token); w.Code != http.StatusOK {
			t.Errorf("%q: status %d, want 200", token, w.Code)
		}
	}
	if len(testRedis.Keys()) != 0 {
		t.Errorf("stored something for invalid tokens: %v", testRedis.Keys())
	}
}

func TestRevokeErrors(t *testing.T) {
	s := newServer()
	if w := postRevoke(s, "", "", "token=x"); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: status %d, want 401", w.Code)
	}
	if w := postRevoke(s, "client2", os.Getenv("SECRET2"), ""); w.Code != http.StatusBadRequest {
		t.Errorf("missing token: status %d, want 400", w.Code)
	}
}

func TestExpiredCodeIsGoneFromRedis(t *testing.T) {
	s := newServer()
	code, _ := s.codes.issue(context.Background(), AuthCode{ClientID: "client1"}, time.Minute)
	testRedis.FastForward(61 * time.Second)
	if testRedis.Exists(codeKey(code)) {
		t.Error("code still stored after its TTL")
	}
}

// Without Redis, codes can't be stored or checked: fail closed.
func TestRedisDown(t *testing.T) {
	s := newServer()
	s.rdb = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	s.codes = &CodeStore{s.rdb}

	if w := postAuthorize(s, validSubmit()); w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" {
		t.Errorf("login: status %d, Location %q; want 503 and no redirect", w.Code, w.Header().Get("Location"))
	}
	if w := postToken(s, "client1", os.Getenv("SECRET1"), exchangeForm("some-code").Encode()); w.Code != http.StatusServiceUnavailable {
		t.Errorf("code exchange: status %d, want 503", w.Code)
	}
	token := s.issueAccessToken("client2", "", []string{"notes:read"})
	if w := postRevoke(s, "client2", os.Getenv("SECRET2"), "token="+token); w.Code != http.StatusServiceUnavailable {
		t.Errorf("revoke: status %d, want 503", w.Code)
	}
}
