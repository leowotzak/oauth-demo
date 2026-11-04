package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// validSubmit is what the login page posts when alice presses Allow: the
// hidden fields from validAuthorizeParams plus her login and decision.
func validSubmit() url.Values {
	f := validAuthorizeParams()
	f.Set("username", "alice")
	f.Set("password", os.Getenv("ALICE_PASSWORD"))
	f.Set("decision", "allow")
	return f
}

func postAuthorize(s *server, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestAuthorizeSubmitIssuesCode(t *testing.T) {
	s := newServer()
	w := postAuthorize(s, validSubmit())

	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (body %s)", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != callback {
		t.Errorf("redirected to %q, want %q", got, callback)
	}
	code, state := loc.Query().Get("code"), loc.Query().Get("state")
	if code == "" || state != "xyz123" {
		t.Fatalf("got code %q state %q, want a code and state xyz123", code, state)
	}
	if loc.Query().Has("error") {
		t.Errorf("unexpected error %q", loc.Query().Get("error"))
	}

	// The stored code must be tied to everything /token will check.
	rec := s.codes.codes[hashSecret(code)]
	if rec == nil {
		t.Fatal("code not in store")
	}
	if rec.clientID != "client1" || rec.userID != "user-1" || rec.redirectURI != callback || rec.used {
		t.Errorf("got %+v", rec)
	}
	if !slices.Equal(rec.scope, []string{"notes:read", "notes:write"}) {
		t.Errorf("scope = %v", rec.scope)
	}
	if rec.challenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("challenge = %q", rec.challenge)
	}
	if ttl := time.Until(rec.expiresAt); ttl <= 0 || ttl > time.Minute {
		t.Errorf("code expires in %v, want within a minute", ttl)
	}
	if _, stored := s.codes.codes[code]; stored {
		t.Error("plaintext code used as a map key")
	}
}

func TestAuthorizeSubmitCodesAreUnique(t *testing.T) {
	s := newServer()
	a := postAuthorize(s, validSubmit()).Header().Get("Location")
	b := postAuthorize(s, validSubmit()).Header().Get("Location")
	if a == b {
		t.Error("two logins produced the same code")
	}
}

func TestAuthorizeSubmitDeny(t *testing.T) {
	s := newServer()
	f := validSubmit()
	f.Set("decision", "deny")
	f.Set("password", "") // denying shouldn't need a password
	assertErrorRedirect(t, postAuthorize(s, f), errAccessDenied, "xyz123")
	if len(s.codes.codes) != 0 {
		t.Error("a code was issued after Deny")
	}
}

func TestAuthorizeSubmitFailedLogin(t *testing.T) {
	cases := map[string]func(url.Values){
		"wrong password":          func(f url.Values) { f.Set("password", "wrong") },
		"another user's password": func(f url.Values) { f.Set("password", os.Getenv("BOB_PASSWORD")) },
		"unknown user":            func(f url.Values) { f.Set("username", "carol") },
		"empty password":          func(f url.Values) { f.Set("password", "") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServer()
			f := validSubmit()
			change(f)
			w := postAuthorize(s, f)

			// Show the page again; don't tell the client anything.
			if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
				t.Fatalf("status %d, Location %q; want 200 and no redirect", w.Code, w.Header().Get("Location"))
			}
			body := w.Body.String()
			if !strings.Contains(body, "Invalid username or password.") {
				t.Error("page doesn't show the login error")
			}
			if !strings.Contains(body, `name="state" value="xyz123"`) {
				t.Error("page lost the request details, so a retry would fail")
			}
			if len(s.codes.codes) != 0 {
				t.Error("a code was issued after a failed login")
			}
		})
	}
}

// The hidden fields could have been edited before submitting, so POST checks
// them all again, with the same two-phase rules as GET.
func TestAuthorizeSubmitRechecksRequest(t *testing.T) {
	t.Run("tampered redirect_uri is never redirected to", func(t *testing.T) {
		s := newServer()
		f := validSubmit()
		f.Set("redirect_uri", "https://evil.example/steal")
		w := postAuthorize(s, f)
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Errorf("status %d, Location %q; want 400 and no redirect", w.Code, w.Header().Get("Location"))
		}
		if len(s.codes.codes) != 0 {
			t.Error("a code was issued")
		}
	})

	cases := []struct {
		name      string
		change    func(url.Values)
		wantError string
	}{
		{"scope widened", func(f url.Values) { f.Set("scope", "notes:read metrics:read") }, errInvalidScope},
		{"PKCE challenge removed", func(f url.Values) { f.Del("code_challenge") }, errInvalidRequest},
		{"PKCE downgraded to plain", func(f url.Values) { f.Set("code_challenge_method", "plain") }, errInvalidRequest},
		{"response_type changed", func(f url.Values) { f.Set("response_type", "token") }, errUnsupportedResponseType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer()
			f := validSubmit()
			c.change(f)
			assertErrorRedirect(t, postAuthorize(s, f), c.wantError, "xyz123")
			if len(s.codes.codes) != 0 {
				t.Error("a code was issued")
			}
		})
	}
}
