package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// fakeAuthServer stands in for auth-server's /introspect. It knows a fixed
// set of tokens and checks that the caller authenticates as notes-api.
func fakeAuthServer(t *testing.T) *httptest.Server {
	tokens := map[string]introspection{
		"read-token":  {Active: true, Scope: "notes:read", ClientID: "client2"},
		"write-token": {Active: true, Scope: "notes:read notes:write", ClientID: "client3"},
		// Authorization code tokens: the same client acting for two users.
		"alice-token": {Active: true, Scope: "notes:read notes:write", ClientID: "client1", Sub: "user-1"},
		"bob-token":   {Active: true, Scope: "notes:read notes:write", ClientID: "client1", Sub: "user-2"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, secret, _ := r.BasicAuth(); id != "notes-api" || secret != "api-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.ParseForm()
		json.NewEncoder(w).Encode(tokens[r.PostForm.Get("token")]) // unknown → {"active":false}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func call(s *server, method, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/notes", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestNotesAPI(t *testing.T) {
	auth := fakeAuthServer(t)
	s := newServer(auth.URL, "notes-api", "api-secret")

	cases := []struct {
		name, method, token, body string
		wantStatus                int
		wantChallenge             string // must appear in WWW-Authenticate
	}{
		{"no token", "GET", "", "", 401, "Bearer"},
		{"unknown token", "GET", "made-up", "", 401, `error="invalid_token"`},
		{"read token can read", "GET", "read-token", "", 200, ""},
		{"read token cannot write", "POST", "read-token", `{"text":"hi"}`, 403, `error="insufficient_scope", scope="notes:write"`},
		{"write token can write", "POST", "write-token", `{"text":"hi"}`, 201, ""},
		{"write token, bad body", "POST", "write-token", `nope`, 400, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := call(s, c.method, c.token, c.body)
			if w.Code != c.wantStatus {
				t.Fatalf("status %d, want %d (body %s)", w.Code, c.wantStatus, w.Body)
			}
			if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, c.wantChallenge) {
				t.Errorf("WWW-Authenticate = %q, want it to contain %q", got, c.wantChallenge)
			}
		})
	}
}

func TestNotesAPIWithWrongCredentials(t *testing.T) {
	// If this service's own secret is wrong, introspection fails and the
	// request can't be checked.
	s := newServer(fakeAuthServer(t).URL, "notes-api", "wrong")
	if w := call(s, "GET", "read-token", ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", w.Code)
	}
}

func TestNotesAPIWhenAuthServerIsDown(t *testing.T) {
	s := newServer("http://127.0.0.1:1/introspect", "notes-api", "api-secret")
	if w := call(s, "GET", "read-token", ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", w.Code)
	}
}

// notesFor calls GET /notes with a token and decodes the response.
func notesFor(t *testing.T, s *server, token string) notesResponse {
	t.Helper()
	w := call(s, "GET", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /notes with %s: status %d", token, w.Code)
	}
	var resp notesResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp
}

// alice and bob use the same client (client1), but each token acts for a
// different user, so each sees only their own notes.
func TestNotesArePerUser(t *testing.T) {
	s := newServer(fakeAuthServer(t).URL, "notes-api", "api-secret")

	alice := notesFor(t, s, "alice-token")
	if alice.Owner != "user-1" || !slices.Equal(alice.Notes, []string{"Buy milk"}) {
		t.Errorf("alice got %+v", alice)
	}

	if w := call(s, "POST", "bob-token", `{"text":"bob's secret"}`); w.Code != http.StatusCreated {
		t.Fatalf("bob POST: status %d", w.Code)
	}
	bob := notesFor(t, s, "bob-token")
	if bob.Owner != "user-2" || !slices.Contains(bob.Notes, "bob's secret") {
		t.Errorf("bob got %+v", bob)
	}
	if slices.Contains(notesFor(t, s, "alice-token").Notes, "bob's secret") {
		t.Error("alice can see bob's note")
	}
}

// Client credentials tokens have no user, so their notes belong to the
// client itself, separate from every user's.
func TestNotesForClientWithoutUser(t *testing.T) {
	s := newServer(fakeAuthServer(t).URL, "notes-api", "api-secret")
	got := notesFor(t, s, "read-token")
	if got.Owner != "client:client2" || got.Notes == nil || len(got.Notes) != 0 {
		t.Errorf("got %+v, want owner client:client2 with an empty list", got)
	}
}
