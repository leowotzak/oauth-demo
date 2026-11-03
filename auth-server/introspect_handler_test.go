package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// postIntrospect calls POST /introspect as the given client.
func postIntrospect(s *server, id, secret, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		r.SetBasicAuth(id, secret)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestIntrospect(t *testing.T) {
	s := newServer()
	api := os.Getenv("NOTES_API_SECRET")
	valid := s.tokens.issue("client3", []string{"notes:read", "notes:write"}, time.Hour)
	expired := s.tokens.issue("client3", []string{"notes:read"}, -time.Second)

	t.Run("active token", func(t *testing.T) {
		w := postIntrospect(s, "notes-api", api, "token="+valid)
		var resp introspectionResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		if w.Code != 200 || !resp.Active || resp.ClientID != "client3" || resp.Scope != "notes:read notes:write" {
			t.Errorf("got %d %+v", w.Code, resp)
		}
	})

	for name, token := range map[string]string{"unknown token": "not-a-token", "expired token": expired} {
		t.Run(name, func(t *testing.T) {
			w := postIntrospect(s, "notes-api", api, "token="+token)
			if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"active":false}` {
				t.Errorf("got %d %s, want 200 {\"active\":false}", w.Code, w.Body)
			}
		})
	}

	errorCases := []struct {
		name, id, secret, body string
		wantStatus             int
		wantError              string
	}{
		{"caller not authenticated", "", "", "token=" + valid, 401, errInvalidClient},
		{"caller has wrong secret", "notes-api", "wrong", "token=" + valid, 401, errInvalidClient},
		{"missing token", "notes-api", api, "", 400, errInvalidRequest},
	}
	for _, c := range errorCases {
		t.Run(c.name, func(t *testing.T) {
			w := postIntrospect(s, c.id, c.secret, c.body)
			var resp errorResponse
			json.Unmarshal(w.Body.Bytes(), &resp)
			if w.Code != c.wantStatus || resp.Error != c.wantError {
				t.Errorf("got %d %q, want %d %q", w.Code, resp.Error, c.wantStatus, c.wantError)
			}
		})
	}
}

func TestNotesAPICannotGetTokens(t *testing.T) {
	w := postToken(newServer(), "notes-api", os.Getenv("NOTES_API_SECRET"), "grant_type=client_credentials")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 unauthorized_client", w.Code)
	}
}
