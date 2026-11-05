package main

import (
	"slices"
	"testing"
	"time"
)

func TestTokenIssueAndLookup(t *testing.T) {
	store := newTokenStore()
	token := store.issue(TokenRecord{clientID: "client2", scope: []string{"notes:read"}}, time.Hour)

	rec, ok := store.lookup(token)
	if !ok {
		t.Fatal("issued token not found")
	}
	if rec.clientID != "client2" || !slices.Equal(rec.scope, []string{"notes:read"}) {
		t.Errorf("got %+v", rec)
	}
	if token == store.issue(TokenRecord{clientID: "client2", scope: []string{"notes:read"}}, time.Hour) {
		t.Error("two issued tokens are identical")
	}
}

func TestTokenLookupFailures(t *testing.T) {
	store := newTokenStore()
	expired := store.issue(TokenRecord{clientID: "client2", scope: []string{"notes:read"}}, -time.Second)

	for name, token := range map[string]string{
		"never issued": "not-a-real-token",
		"expired":      expired,
	} {
		if _, ok := store.lookup(token); ok {
			t.Errorf("%s: lookup succeeded, want failure", name)
		}
	}
}
