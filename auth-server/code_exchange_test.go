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

// The PKCE example from RFC 7636 Appendix B. Its challenge is the one
// validAuthorizeParams uses.
const (
	exampleVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	exampleChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestPKCEMatches(t *testing.T) {
	if !pkceMatches(exampleVerifier, exampleChallenge) {
		t.Error("RFC 7636 example verifier doesn't match its challenge")
	}
	for _, v := range []string{"", "wrong", exampleChallenge} {
		if pkceMatches(v, exampleChallenge) {
			t.Errorf("verifier %q matched", v)
		}
	}
}

// issueTestCode stores a code for alice and client1, as POST /authorize would.
func issueTestCode(s *server, ttl time.Duration) string {
	return s.codes.issue(AuthCode{
		clientID:    "client1",
		userID:      "user-1",
		redirectURI: callback,
		scope:       []string{"notes:read"},
		challenge:   exampleChallenge,
	}, ttl)
}

// exchangeForm is a correct code exchange; tests change one field at a time.
func exchangeForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callback},
		"code_verifier": {exampleVerifier},
	}
}

func TestCodeExchangeSuccess(t *testing.T) {
	s := newServer()
	form := exchangeForm(issueTestCode(s, time.Minute))
	form.Set("scope", "notes:write") // ignored: the scope comes from the code

	w := postToken(s, "client1", os.Getenv("SECRET1"), form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	var resp tokenResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.TokenType != "Bearer" || resp.Scope != "notes:read" {
		t.Errorf("got %+v, want a Bearer token with the code's scope notes:read", resp)
	}
	if claims := verifyTestToken(t, s, resp.AccessToken); claims.ClientID != "client1" || claims.Subject != "user-1" {
		t.Errorf("claims %+v, want client1 acting for user-1", claims)
	}
}

func TestCodeExchangeErrors(t *testing.T) {
	s1 := os.Getenv("SECRET1")

	cases := []struct {
		name       string
		ttl        time.Duration
		change     func(url.Values)
		id, secret string
		wantStatus int
		wantError  string
	}{
		{"missing code", time.Minute, func(f url.Values) { f.Del("code") }, "client1", s1, 400, errInvalidRequest},
		{"unknown code", time.Minute, func(f url.Values) { f.Set("code", "made-up") }, "client1", s1, 400, errInvalidGrant},
		{"expired code", -time.Second, nil, "client1", s1, 400, errInvalidGrant},
		{"different redirect_uri", time.Minute, func(f url.Values) { f.Set("redirect_uri", callback+"/") }, "client1", s1, 400, errInvalidGrant},
		{"missing redirect_uri", time.Minute, func(f url.Values) { f.Del("redirect_uri") }, "client1", s1, 400, errInvalidGrant},
		{"wrong code_verifier", time.Minute, func(f url.Values) { f.Set("code_verifier", "wrong") }, "client1", s1, 400, errInvalidGrant},
		{"missing code_verifier", time.Minute, func(f url.Values) { f.Del("code_verifier") }, "client1", s1, 400, errInvalidGrant},
		{"challenge sent as verifier", time.Minute, func(f url.Values) { f.Set("code_verifier", exampleChallenge) }, "client1", s1, 400, errInvalidGrant},
		{"client not authenticated", time.Minute, nil, "client1", "wrong", 401, errInvalidClient},
		{"client not allowed this grant", time.Minute, nil, "client2", os.Getenv("SECRET2"), 400, errUnauthorizedClient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer()
			form := exchangeForm(issueTestCode(s, c.ttl))
			if c.change != nil {
				c.change(form)
			}
			w := postToken(s, c.id, c.secret, form.Encode())
			var resp errorResponse
			json.Unmarshal(w.Body.Bytes(), &resp)
			if w.Code != c.wantStatus || resp.Error != c.wantError {
				t.Errorf("got %d %q (%s), want %d %q", w.Code, resp.Error, resp.ErrorDescription, c.wantStatus, c.wantError)
			}
			if strings.Contains(w.Body.String(), "access_token") {
				t.Error("a token was issued")
			}
		})
	}
}

func TestCodeExchangeOtherClient(t *testing.T) {
	// client3 authenticates correctly and may use this grant, but the code
	// was issued to client1.
	s := newServer()
	s.clients["client3"].grantTypes = append(s.clients["client3"].grantTypes, "authorization_code")
	w := postToken(s, "client3", os.Getenv("SECRET3"), exchangeForm(issueTestCode(s, time.Minute)).Encode())

	var resp errorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != errInvalidGrant {
		t.Errorf("got %d %q, want invalid_grant", w.Code, resp.Error)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	s := newServer()
	form := exchangeForm(issueTestCode(s, time.Minute)).Encode()

	if w := postToken(s, "client1", os.Getenv("SECRET1"), form); w.Code != http.StatusOK {
		t.Fatalf("first exchange: status %d, body %s", w.Code, w.Body)
	}
	if w := postToken(s, "client1", os.Getenv("SECRET1"), form); w.Code != http.StatusBadRequest {
		t.Errorf("second exchange: status %d, want 400 invalid_grant", w.Code)
	}
}

func TestFailedExchangeBurnsCode(t *testing.T) {
	// One wrong verifier and the code is gone: an attacker with a stolen code
	// gets one guess, not many.
	s := newServer()
	code := issueTestCode(s, time.Minute)

	bad := exchangeForm(code)
	bad.Set("code_verifier", "guess")
	postToken(s, "client1", os.Getenv("SECRET1"), bad.Encode())

	if w := postToken(s, "client1", os.Getenv("SECRET1"), exchangeForm(code).Encode()); w.Code != http.StatusBadRequest {
		t.Errorf("code still worked after a failed attempt: status %d", w.Code)
	}
}

// The whole server-side flow: alice logs in at /authorize, and client1
// exchanges the code it receives.
func TestAuthorizationCodeFlow(t *testing.T) {
	s := newServer()
	w := postAuthorize(s, validSubmit())
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code from /authorize: %d %s", w.Code, w.Header().Get("Location"))
	}

	w = postToken(s, "client1", os.Getenv("SECRET1"), exchangeForm(code).Encode())
	var resp tokenResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || resp.Scope != "notes:read notes:write" {
		t.Fatalf("got %d %+v, want 200 with the consented scope", w.Code, resp)
	}
	claims := verifyTestToken(t, s, resp.AccessToken)
	if claims.Subject != "user-1" || claims.ClientID != "client1" {
		t.Errorf("token is for client %q user %q, want client1 acting for user-1 (alice)", claims.ClientID, claims.Subject)
	}
}
