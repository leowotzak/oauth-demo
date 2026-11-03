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
