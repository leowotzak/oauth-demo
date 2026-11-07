package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// login runs alice's full login as client1 (authorize, then code exchange)
// and returns the token response.
func login(t *testing.T, s *server) tokenResponse {
	t.Helper()
	loc, _ := url.Parse(postAuthorize(s, validSubmit()).Header().Get("Location"))
	w := postToken(s, "client1", os.Getenv("SECRET1"), exchangeForm(loc.Query().Get("code")).Encode())
	var resp tokenResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || resp.RefreshToken == "" {
		t.Fatalf("login: status %d, body %s", w.Code, w.Body)
	}
	return resp
}

// refresh calls /token with grant_type=refresh_token.
func refresh(s *server, id, secret, refreshToken, scope string) (int, tokenResponse, errorResponse) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if scope != "" {
		form.Set("scope", scope)
	}
	w := postToken(s, id, secret, form.Encode())
	var ok tokenResponse
	var bad errorResponse
	json.Unmarshal(w.Body.Bytes(), &ok)
	json.Unmarshal(w.Body.Bytes(), &bad)
	return w.Code, ok, bad
}

func TestOnlyLoginsGetRefreshTokens(t *testing.T) {
	s := newServer()
	if resp := login(t, s); resp.RefreshToken == "" {
		t.Error("code exchange gave no refresh token")
	}
	// Client credentials: the client can just authenticate again (§4.4.3).
	w := postToken(s, "client2", os.Getenv("SECRET2"), "grant_type=client_credentials")
	if strings.Contains(w.Body.String(), "refresh_token") {
		t.Errorf("client credentials got a refresh token: %s", w.Body)
	}
}

func TestRefreshRotates(t *testing.T) {
	s := newServer()
	first := login(t, s)

	code, second, _ := refresh(s, "client1", os.Getenv("SECRET1"), first.RefreshToken, "")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	// A new access token for the same login...
	claims := verifyTestToken(t, s, second.AccessToken)
	if claims.Subject != "user-1" || claims.ClientID != "client1" || second.Scope != "notes:read notes:write" {
		t.Errorf("refreshed token: claims %+v, scope %q", claims, second.Scope)
	}
	// ...and a new refresh token, replacing the old one.
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatalf("refresh token not rotated: %q", second.RefreshToken)
	}
	if testRedis.Exists(refreshKey(first.RefreshToken)) {
		t.Error("old refresh token still live")
	}
	if !testRedis.Exists(refreshKey(second.RefreshToken)) {
		t.Error("new refresh token not stored")
	}
	if testRedis.Exists("refresh:" + second.RefreshToken) {
		t.Error("plaintext refresh token used as a Redis key")
	}
	// The chain keeps going.
	if code, _, _ := refresh(s, "client1", os.Getenv("SECRET1"), second.RefreshToken, ""); code != http.StatusOK {
		t.Errorf("second refresh: status %d", code)
	}
}

// The core of rotation: an old token coming back means someone copied it, so
// the whole login is shut down, including the current refresh token and the
// latest access token.
func TestReusedRefreshTokenRevokesTheFamily(t *testing.T) {
	s := newServer()
	stolen := login(t, s).RefreshToken
	_, current, _ := refresh(s, "client1", os.Getenv("SECRET1"), stolen, "")

	// The thief (or the real client) presents the already-rotated token.
	code, _, e := refresh(s, "client1", os.Getenv("SECRET1"), stolen, "")
	if code != http.StatusBadRequest || e.Error != errInvalidGrant || !strings.Contains(e.ErrorDescription, "revoked") {
		t.Fatalf("reuse: status %d, %+v", code, e)
	}
	// The newest refresh token stops working too...
	if code, _, _ := refresh(s, "client1", os.Getenv("SECRET1"), current.RefreshToken, ""); code != http.StatusBadRequest {
		t.Errorf("current refresh token still works after reuse: status %d", code)
	}
	// ...and so does the latest access token, via the deny list.
	if !testRedis.Exists(revokedKey(jtiOf(t, s, current.AccessToken))) {
		t.Error("latest access token not revoked")
	}
}

func TestRefreshScope(t *testing.T) {
	s := newServer()
	first := login(t, s) // approved: notes:read notes:write

	// Asking for less is fine (§6)...
	code, narrow, _ := refresh(s, "client1", os.Getenv("SECRET1"), first.RefreshToken, "notes:read")
	if code != http.StatusOK || narrow.Scope != "notes:read" || verifyTestToken(t, s, narrow.AccessToken).Scope != "notes:read" {
		t.Fatalf("narrowed: status %d, scope %q", code, narrow.Scope)
	}
	// ...but the refresh token keeps the full approved scope.
	if _, next, _ := refresh(s, "client1", os.Getenv("SECRET1"), narrow.RefreshToken, ""); next.Scope != "notes:read notes:write" {
		t.Errorf("after narrowing once, full refresh gave %q", next.Scope)
	}

	// Asking for more than was approved is refused.
	other := login(t, s)
	if code, _, e := refresh(s, "client1", os.Getenv("SECRET1"), other.RefreshToken, "notes:read metrics:read"); code != http.StatusBadRequest || e.Error != errInvalidScope {
		t.Errorf("widened: status %d, %+v", code, e)
	}
}

func TestRefreshErrors(t *testing.T) {
	s := newServer()
	s.clients["client3"].grantTypes = append(s.clients["client3"].grantTypes, "refresh_token")

	cases := []struct {
		name, id, secret string
		token            func() string
		wantStatus       int
		wantError        string
	}{
		{"missing refresh_token", "client1", os.Getenv("SECRET1"), func() string { return "" }, 400, errInvalidRequest},
		{"unknown refresh token", "client1", os.Getenv("SECRET1"), func() string { return "made-up" }, 400, errInvalidGrant},
		{"issued to another client", "client3", os.Getenv("SECRET3"), func() string { return login(t, s).RefreshToken }, 400, errInvalidGrant},
		{"client not allowed to refresh", "client2", os.Getenv("SECRET2"), func() string { return login(t, s).RefreshToken }, 400, errUnauthorizedClient},
		{"wrong client secret", "client1", "wrong", func() string { return login(t, s).RefreshToken }, 401, errInvalidClient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, ok, e := refresh(s, c.id, c.secret, c.token(), "")
			if code != c.wantStatus || e.Error != c.wantError || ok.AccessToken != "" {
				t.Errorf("got %d %q, want %d %q", code, e.Error, c.wantStatus, c.wantError)
			}
		})
	}
}

// Rotation never extends a login: after 24 hours from the original login,
// the family ends, however recently it was refreshed.
func TestLoginLifetimeIsAbsolute(t *testing.T) {
	s := newServer()
	// Move the server's clock and the fake Redis's clock together.
	start := time.Now()
	s.now = func() time.Time { return start }
	advance := func(d time.Duration) {
		start = start.Add(d)
		testRedis.FastForward(d)
	}
	token := login(t, s).RefreshToken

	advance(23 * time.Hour)
	code, next, _ := refresh(s, "client1", os.Getenv("SECRET1"), token, "")
	if code != http.StatusOK {
		t.Fatalf("refresh at 23h: status %d", code)
	}
	if ttl := testRedis.TTL(refreshKey(next.RefreshToken)); ttl > time.Hour {
		t.Errorf("rotated token lives %v, want at most the hour left in the login", ttl)
	}
	advance(time.Hour + time.Second)
	if code, _, _ := refresh(s, "client1", os.Getenv("SECRET1"), next.RefreshToken, ""); code != http.StatusBadRequest {
		t.Errorf("refresh after 24h: status %d, want 400", code)
	}
}

// Revoking a refresh token (what logging out does) ends the whole login.
func TestRevokeRefreshTokenEndsLogin(t *testing.T) {
	s := newServer()
	tokens := login(t, s)

	if w := postRevoke(s, "client1", os.Getenv("SECRET1"), url.Values{"token": {tokens.RefreshToken}}.Encode()); w.Code != http.StatusOK {
		t.Fatalf("revoke: status %d", w.Code)
	}
	if code, _, _ := refresh(s, "client1", os.Getenv("SECRET1"), tokens.RefreshToken, ""); code != http.StatusBadRequest {
		t.Error("refresh token still works after revoking it")
	}
	if !testRedis.Exists(revokedKey(jtiOf(t, s, tokens.AccessToken))) {
		t.Error("the login's access token wasn't revoked with it")
	}

	// Another client can't revoke it.
	other := login(t, s)
	postRevoke(s, "client2", os.Getenv("SECRET2"), url.Values{"token": {other.RefreshToken}}.Encode())
	if code, _, _ := refresh(s, "client1", os.Getenv("SECRET1"), other.RefreshToken, ""); code != http.StatusOK {
		t.Error("client2 revoked client1's refresh token")
	}
}
