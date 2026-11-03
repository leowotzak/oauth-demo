package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// postToken sends POST /token with a form body, optionally with Basic auth.
func postToken(s *server, id, secret, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		r.SetBasicAuth(id, secret)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestTokenEndpointSuccess(t *testing.T) {
	s := newServer()
	s2, s3 := os.Getenv("SECRET2"), os.Getenv("SECRET3")

	cases := []struct {
		name, id, secret, body, wantScope string
	}{
		{"scope omitted → defaults", "client2", s2, "grant_type=client_credentials", "notes:read"},
		{"explicit scope", "client2", s2, "grant_type=client_credentials&scope=notes:read", "notes:read"},
		{"credentials in body", "", "", "grant_type=client_credentials&client_id=client2&client_secret=" + s2, "notes:read"},
		{"several scopes", "client3", s3, "grant_type=client_credentials&scope=notes:read+metrics:read", "notes:read metrics:read"},
		{"defaults narrower than allowed", "client3", s3, "grant_type=client_credentials", "notes:read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := postToken(s, c.id, c.secret, c.body)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", w.Code, w.Body)
			}
			var resp tokenResponse
			json.Unmarshal(w.Body.Bytes(), &resp)
			if resp.TokenType != "Bearer" || resp.ExpiresIn != 3600 || resp.Scope != c.wantScope {
				t.Errorf("got %+v, want scope %q", resp, c.wantScope)
			}
			if _, ok := s.tokens.lookup(resp.AccessToken); !ok {
				t.Error("issued token not in store")
			}
		})
	}
}

func TestTokenEndpointErrors(t *testing.T) {
	s := newServer()
	s1, s2, s3 := os.Getenv("SECRET1"), os.Getenv("SECRET2"), os.Getenv("SECRET3")

	cases := []struct {
		name, id, secret, body string
		wantStatus             int
		wantError              string
	}{
		{"no credentials", "", "", "grant_type=client_credentials", 401, errInvalidClient},
		{"wrong secret", "client2", "wrong", "grant_type=client_credentials", 401, errInvalidClient},
		{"unknown client", "client4", s2, "grant_type=client_credentials", 401, errInvalidClient},
		{"missing grant_type", "client2", s2, "scope=notes:read", 400, errInvalidRequest},
		{"password grant", "client2", s2, "grant_type=password", 400, errUnsupportedGrantType},
		{"client not allowed client_credentials", "client1", s1, "grant_type=client_credentials", 400, errUnauthorizedClient},
		{"scope not allowed", "client2", s2, "grant_type=client_credentials&scope=notes:write", 400, errInvalidScope},
		{"scope wrong case", "client2", s2, "grant_type=client_credentials&scope=NOTES:READ", 400, errInvalidScope},
		{"one bad scope fails the lot", "client3", s3, "grant_type=client_credentials&scope=notes:read+notes:delete", 400, errInvalidScope},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := postToken(s, c.id, c.secret, c.body)
			var resp errorResponse
			json.Unmarshal(w.Body.Bytes(), &resp)
			if w.Code != c.wantStatus || resp.Error != c.wantError {
				t.Errorf("got %d %q, want %d %q", w.Code, resp.Error, c.wantStatus, c.wantError)
			}
		})
	}
	if len(s.tokens.tokens) != 0 {
		t.Error("a token was issued on a failed request")
	}
}

func TestTokenEndpointRejectsGET(t *testing.T) {
	w := httptest.NewRecorder()
	newServer().routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/token", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status %d, want 405", w.Code)
	}
}
