package main

import (
	"os"
	"testing"
)

func TestAuthenticateClient(t *testing.T) {
	clients := newClientRegistry()
	s1, s2 := os.Getenv("SECRET1"), os.Getenv("SECRET2")

	cases := []struct {
		name, id, secret string
		ok               bool
	}{
		{"correct secret", "client2", s2, true},
		{"wrong secret", "client2", "wrong", false},
		{"another client's secret", "client2", s1, false},
		{"the hash instead of the secret", "client2", os.Getenv("SECRET2_HASH"), false},
		{"unknown client", "client4", s2, false},
		{"empty id", "", s2, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, ok := authenticateClient(clients, c.id, c.secret)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && client.id != c.id {
				t.Errorf("returned client %q, want %q", client.id, c.id)
			}
		})
	}
}

func TestAllowsRedirect(t *testing.T) {
	client1 := newClientRegistry()["client1"]

	cases := []struct {
		uri     string
		allowed bool
	}{
		{"http://localhost:9000/callback", true},
		{"http://localhost:9000/callback/", false},          // trailing slash
		{"http://localhost:9000/callback?next=evil", false}, // extra query
		{"http://localhost:9000/callback/../steal", false},  // path tricks
		{"http://localhost:9000/callback.evil.com", false},  // a prefix match would allow this
		{"http://localhost:9001/callback", false},           // different port
		{"https://localhost:9000/callback", false},          // different scheme
		{"HTTP://LOCALHOST:9000/callback", false},           // exact string, no normalizing
		{"", false},
	}
	for _, c := range cases {
		if got := client1.allowsRedirect(c.uri); got != c.allowed {
			t.Errorf("allowsRedirect(%q) = %v, want %v", c.uri, got, c.allowed)
		}
	}

	// Clients without registered URIs can't use /authorize at all.
	if newClientRegistry()["client2"].allowsRedirect("http://localhost:9000/callback") {
		t.Error("client2 has no redirect URIs but allowed one")
	}
}
