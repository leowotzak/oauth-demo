package main

import (
	"os"
	"testing"
)

func TestAuthenticateUser(t *testing.T) {
	users := newUserRegistry()
	alice, bob := os.Getenv("ALICE_PASSWORD"), os.Getenv("BOB_PASSWORD")

	cases := []struct {
		name, username, password, wantID string // wantID empty → should fail
	}{
		{"alice, right password", "alice", alice, "user-1"},
		{"bob, right password", "bob", bob, "user-2"},
		{"wrong password", "alice", "wrong", ""},
		{"another user's password", "alice", bob, ""},
		{"the hash instead of the password", "alice", os.Getenv("ALICE_PASSWORD_HASH"), ""},
		{"username wrong case", "Alice", alice, ""},
		{"unknown user", "carol", alice, ""},
		{"empty password", "alice", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, ok := authenticateUser(users, c.username, c.password)
			if ok != (c.wantID != "") {
				t.Fatalf("ok = %v, want %v", ok, c.wantID != "")
			}
			if ok && u.id != c.wantID {
				t.Errorf("user id = %q, want %q", u.id, c.wantID)
			}
		})
	}
}
