package main

import (
	"slices"
	"sync"
	"testing"
	"time"
)

func TestTokenIssueAndLookup(t *testing.T) {
	store := newTokenStore()
	token, _ := store.issue("client2", []string{"notes:read"}, time.Hour)

	rec, ok := store.lookup(token)
	if !ok {
		t.Fatal("issued token not found")
	}
	if rec.clientID != "client2" {
		t.Errorf("clientID = %q, want client2", rec.clientID)
	}
	if !slices.Equal(rec.scope, []string{"notes:read"}) {
		t.Errorf("scope = %v, want [notes:read]", rec.scope)
	}
}

func TestTokenLookupFailures(t *testing.T) {
	store := newTokenStore()
	token, _ := store.issue("client2", []string{"notes:read"}, time.Hour)
	expired, _ := store.issue("client2", []string{"notes:read"}, -time.Second)

	cases := []struct {
		name  string
		token string
	}{
		{"never issued", "not-a-real-token"},
		{"empty", ""},
		{"expired", expired},
		{"token's hash instead of token", hashSecret(token)},
		{"token with extra character", token + "x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if rec, ok := store.lookup(c.token); ok || rec != nil {
				t.Errorf("lookup succeeded, want failure")
			}
		})
	}
}

func TestTokensAreUnique(t *testing.T) {
	store := newTokenStore()
	a, _ := store.issue("client2", []string{"notes:read"}, time.Hour)
	b, _ := store.issue("client2", []string{"notes:read"}, time.Hour)
	if a == b {
		t.Fatal("two issued tokens are identical")
	}
}

func TestTokenStoreStoresHashesOnly(t *testing.T) {
	store := newTokenStore()
	token, _ := store.issue("client2", []string{"notes:read"}, time.Hour)
	if _, found := store.tokens[token]; found {
		t.Fatal("plaintext token used as a map key")
	}
}

// Run with -race to check the mutex.
func TestTokenStoreConcurrent(t *testing.T) {
	store := newTokenStore()
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			token, _ := store.issue("client2", []string{"notes:read"}, time.Hour)
			if _, ok := store.lookup(token); !ok {
				t.Error("token issued concurrently not found")
			}
		})
	}
	wg.Wait()
	if len(store.tokens) != 50 {
		t.Errorf("store has %d tokens, want 50", len(store.tokens))
	}
}
