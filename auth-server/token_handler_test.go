package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type tokenRequest struct {
	method      string
	query       string // appended to the URL, e.g. "grant_type=client_credentials"
	contentType string // defaults to form-encoded
	basicID     string // if set, sent as HTTP Basic
	basicSecret string
	body        string // raw body, sent as is
}

func doTokenRequest(t *testing.T, s *server, req tokenRequest) *httptest.ResponseRecorder {
	t.Helper()
	if req.method == "" {
		req.method = http.MethodPost
	}
	target := "/token"
	if req.query != "" {
		target += "?" + req.query
	}
	r := httptest.NewRequest(req.method, target, strings.NewReader(req.body))
	if req.contentType == "" {
		req.contentType = "application/x-www-form-urlencoded"
	}
	r.Header.Set("Content-Type", req.contentType)
	if req.basicID != "" {
		r.SetBasicAuth(req.basicID, req.basicSecret)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func newTestServer(t *testing.T) (*server, map[string]string) {
	t.Helper()
	env := loadDotEnv(t)
	return newServer(), env
}

func TestTokenEndpointSuccess(t *testing.T) {
	s, env := newTestServer(t)

	cases := []struct {
		name      string
		req       tokenRequest
		wantScope string
	}{
		{"basic auth, scope omitted → defaults",
			tokenRequest{basicID: "client2", basicSecret: env["SECRET2"], body: "grant_type=client_credentials"},
			"notes:read"},
		{"basic auth, explicit scope",
			tokenRequest{basicID: "client2", basicSecret: env["SECRET2"], body: "grant_type=client_credentials&scope=notes:read"},
			"notes:read"},
		{"credentials in body",
			tokenRequest{body: "grant_type=client_credentials&client_id=client2&client_secret=" + url.QueryEscape(env["SECRET2"])},
			"notes:read"},
		{"several scopes",
			tokenRequest{basicID: "client3", basicSecret: env["SECRET3"], body: "grant_type=client_credentials&scope=notes:read+notes:write+metrics:read"},
			"notes:read notes:write metrics:read"},
		{"duplicate scope is dropped",
			tokenRequest{basicID: "client3", basicSecret: env["SECRET3"], body: "grant_type=client_credentials&scope=notes:read%20notes:read"},
			"notes:read"},
		{"client3 default is narrower than allowed",
			tokenRequest{basicID: "client3", basicSecret: env["SECRET3"], body: "grant_type=client_credentials"},
			"notes:read"},
		{"content type with charset",
			tokenRequest{basicID: "client2", basicSecret: env["SECRET2"], contentType: "application/x-www-form-urlencoded; charset=UTF-8", body: "grant_type=client_credentials"},
			"notes:read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := doTokenRequest(t, s, c.req)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", w.Code, w.Body)
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := w.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q, want no-cache", got)
			}

			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("bad JSON: %v", err)
			}
			if resp["token_type"] != "Bearer" {
				t.Errorf("token_type = %v", resp["token_type"])
			}
			if resp["expires_in"] != float64(3600) {
				t.Errorf("expires_in = %v", resp["expires_in"])
			}
			if resp["scope"] != c.wantScope {
				t.Errorf("scope = %q, want %q", resp["scope"], c.wantScope)
			}
			if _, has := resp["refresh_token"]; has {
				t.Error("refresh_token issued for client_credentials (§4.4.3)")
			}

			// The token must actually be usable.
			rec, ok := s.tokens.lookup(resp["access_token"].(string))
			if !ok {
				t.Fatal("issued token not in store")
			}
			if strings.Join(rec.scope, " ") != c.wantScope {
				t.Errorf("stored scope = %v, want %q", rec.scope, c.wantScope)
			}
		})
	}
}

func TestTokenEndpointErrors(t *testing.T) {
	s, env := newTestServer(t)
	s2 := env["SECRET2"]

	cases := []struct {
		name       string
		req        tokenRequest
		wantStatus int
		wantError  string // empty when the response isn't an OAuth error (405)
	}{
		// Request format
		{"GET", tokenRequest{method: http.MethodGet}, http.StatusMethodNotAllowed, ""},
		{"JSON body",
			tokenRequest{basicID: "client2", basicSecret: s2, contentType: "application/json", body: `{"grant_type":"client_credentials"}`},
			400, errInvalidRequest},
		{"params in query string are ignored",
			tokenRequest{basicID: "client2", basicSecret: s2, query: "grant_type=client_credentials"},
			400, errInvalidRequest},
		{"repeated parameter",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=client_credentials&grant_type=client_credentials"},
			400, errInvalidRequest},

		// Client authentication
		{"no credentials",
			tokenRequest{body: "grant_type=client_credentials"},
			401, errInvalidClient},
		{"wrong secret",
			tokenRequest{basicID: "client2", basicSecret: "wrong", body: "grant_type=client_credentials"},
			401, errInvalidClient},
		{"unknown client",
			tokenRequest{basicID: "client4", basicSecret: s2, body: "grant_type=client_credentials"},
			401, errInvalidClient},
		{"wrong secret in body",
			tokenRequest{body: "grant_type=client_credentials&client_id=client2&client_secret=wrong"},
			401, errInvalidClient},
		{"basic and body secret together",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=client_credentials&client_id=client2&client_secret=" + url.QueryEscape(s2)},
			400, errInvalidRequest},

		// Grant type
		{"missing grant_type",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "scope=notes:read"},
			400, errInvalidRequest},
		{"password grant",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=password"},
			400, errUnsupportedGrantType},
		{"made-up grant",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=magic"},
			400, errUnsupportedGrantType},
		{"grant_type wrong case",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=Client_Credentials"},
			400, errUnsupportedGrantType},
		{"client not allowed client_credentials",
			tokenRequest{basicID: "client1", basicSecret: env["SECRET1"], body: "grant_type=client_credentials"},
			400, errUnauthorizedClient},
		{"client2 not allowed authorization_code",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=authorization_code"},
			400, errUnauthorizedClient},
		{"allowed but not implemented yet",
			tokenRequest{basicID: "client1", basicSecret: env["SECRET1"], body: "grant_type=authorization_code"},
			400, errUnsupportedGrantType},

		// Scope
		{"scope not allowed",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=client_credentials&scope=notes:write"},
			400, errInvalidScope},
		{"scope wrong case",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=client_credentials&scope=NOTES:READ"},
			400, errInvalidScope},
		{"one bad scope fails the lot",
			tokenRequest{basicID: "client3", basicSecret: env["SECRET3"], body: "grant_type=client_credentials&scope=notes:read+notes:delete"},
			400, errInvalidScope},
		{"wrong resource",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=client_credentials&scope=metrics:read"},
			400, errInvalidScope},
		{"empty scope",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=client_credentials&scope="},
			400, errInvalidScope},
		{"double space in scope",
			tokenRequest{basicID: "client3", basicSecret: env["SECRET3"], body: "grant_type=client_credentials&scope=notes:read%20%20notes:write"},
			400, errInvalidScope},
		{"trailing space in scope",
			tokenRequest{basicID: "client2", basicSecret: s2, body: "grant_type=client_credentials&scope=notes:read%20"},
			400, errInvalidScope},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(s.tokens.tokens)
			w := doTokenRequest(t, s, c.req)

			if w.Code != c.wantStatus {
				t.Fatalf("status %d, want %d (body %s)", w.Code, c.wantStatus, w.Body)
			}
			if len(s.tokens.tokens) != before {
				t.Error("a token was issued on a failed request")
			}
			if c.wantError == "" {
				return
			}

			var resp errorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("bad JSON: %v (body %s)", err, w.Body)
			}
			if resp.Error != c.wantError {
				t.Errorf("error = %q, want %q", resp.Error, c.wantError)
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if c.wantStatus == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate")
			}
		})
	}
}

// RFC 6749 §2.3.1: the client ID and secret are form-urlencoded before
// Basic encoding. Build the header by hand to check the server decodes it.
func TestTokenEndpointBasicAuthIsURLDecoded(t *testing.T) {
	s, env := newTestServer(t)
	creds := url.QueryEscape("client2") + ":" + url.QueryEscape(env["SECRET2"])

	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
}
