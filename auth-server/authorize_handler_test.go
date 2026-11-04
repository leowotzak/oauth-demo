package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const callback = "http://localhost:9000/callback"

// validAuthorizeParams is a correct request from client1. Tests change or
// remove one parameter at a time.
func validAuthorizeParams() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"client1"},
		"redirect_uri":          {callback},
		"scope":                 {"notes:read notes:write"},
		"state":                 {"xyz123"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
}

func getAuthorize(s *server, params url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
	return w
}

func TestAuthorizeShowsLoginPage(t *testing.T) {
	w := getAuthorize(newServer(), validAuthorizeParams())

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		`action="/authorize"`,
		`name="client_id" value="client1"`,
		`name="redirect_uri" value="http://localhost:9000/callback"`,
		`name="scope" value="notes:read notes:write"`,
		`name="state" value="xyz123"`,
		`name="code_challenge" value="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"`,
		`Read your notes`,
		`name="password"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("page can be framed (clickjacking)")
	}
}

func TestAuthorizeDefaultScope(t *testing.T) {
	p := validAuthorizeParams()
	p.Del("scope")
	if body := getAuthorize(newServer(), p).Body.String(); !strings.Contains(body, `name="scope" value="notes:read"`) {
		t.Error("omitted scope should fall back to client1's default, notes:read")
	}
}

func TestAuthorizeEscapesInput(t *testing.T) {
	p := validAuthorizeParams()
	p.Set("state", `"><script>alert(1)</script>`)
	if body := getAuthorize(newServer(), p).Body.String(); strings.Contains(body, "<script>alert(1)") {
		t.Error("state was inserted into the page unescaped (XSS)")
	}
}

// Phase 1: a bad client or redirect URI must give an error page, never a redirect.
func TestAuthorizeNeverRedirectsToUntrustedURI(t *testing.T) {
	cases := map[string]func(url.Values){
		"unknown client":                 func(p url.Values) { p.Set("client_id", "client4") },
		"missing client_id":              func(p url.Values) { p.Del("client_id") },
		"client with no redirect URIs":   func(p url.Values) { p.Set("client_id", "client2") },
		"unregistered redirect_uri":      func(p url.Values) { p.Set("redirect_uri", "https://evil.example/steal") },
		"redirect_uri with extra path":   func(p url.Values) { p.Set("redirect_uri", callback+".evil.com") },
		"missing redirect_uri":           func(p url.Values) { p.Del("redirect_uri") },
		"bad redirect_uri and bad scope": func(p url.Values) { p.Set("redirect_uri", "https://evil.example"); p.Set("scope", "admin") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := validAuthorizeParams()
			change(p)
			w := getAuthorize(newServer(), p)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400", w.Code)
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Errorf("redirected to %q; must not redirect", loc)
			}
		})
	}
}

// Phase 2: other errors redirect back to the client with error and state.
func TestAuthorizeRedirectsErrorsToClient(t *testing.T) {
	cases := []struct {
		name      string
		change    func(url.Values)
		wantError string
	}{
		{"implicit grant requested", func(p url.Values) { p.Set("response_type", "token") }, errUnsupportedResponseType},
		{"missing response_type", func(p url.Values) { p.Del("response_type") }, errUnsupportedResponseType},
		{"scope not allowed", func(p url.Values) { p.Set("scope", "notes:read metrics:read") }, errInvalidScope},
		{"missing PKCE challenge", func(p url.Values) { p.Del("code_challenge") }, errInvalidRequest},
		{"plain PKCE method", func(p url.Values) { p.Set("code_challenge_method", "plain") }, errInvalidRequest},
		{"missing PKCE method", func(p url.Values) { p.Del("code_challenge_method") }, errInvalidRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := validAuthorizeParams()
			c.change(p)
			assertErrorRedirect(t, getAuthorize(newServer(), p), c.wantError, "xyz123")
		})
	}

	t.Run("client not allowed the authorization code flow", func(t *testing.T) {
		s := newServer()
		s.clients["client1"].grantTypes = []string{"client_credentials"}
		assertErrorRedirect(t, getAuthorize(s, validAuthorizeParams()), errUnauthorizedClient, "xyz123")
	})

	t.Run("no state sent, none returned", func(t *testing.T) {
		p := validAuthorizeParams()
		p.Del("state")
		p.Set("response_type", "token")
		assertErrorRedirect(t, getAuthorize(newServer(), p), errUnsupportedResponseType, "")
	})
}

func assertErrorRedirect(t *testing.T, w *httptest.ResponseRecorder, wantError, wantState string) {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (body %s)", w.Code, w.Body)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != callback {
		t.Errorf("redirected to %q, want %q", got, callback)
	}
	q := loc.Query()
	if q.Get("error") != wantError {
		t.Errorf("error = %q, want %q", q.Get("error"), wantError)
	}
	if q.Get("state") != wantState || q.Has("state") != (wantState != "") {
		t.Errorf("state = %q (present %v), want %q", q.Get("state"), q.Has("state"), wantState)
	}
}
