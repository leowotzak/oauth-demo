package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// loadDotEnv reads KEY=VALUE lines from .env into the test's environment
// (restored automatically when the test ends) and returns them.
func loadDotEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(".env")
	if err != nil {
		t.Fatalf("open .env: %v", err)
	}
	defer f.Close()

	vars := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vars[k] = v
		t.Setenv(k, v)
	}
	return vars
}

func TestRegistryLookup(t *testing.T) {
	loadDotEnv(t)
	reg := newClientRegistry()

	cases := []struct {
		id    string
		found bool
	}{
		{"client1", true},
		{"client2", true},
		{"client3", true},
		{"client4", false},
		{"CLIENT2", false}, // client IDs are exact strings
		{"", false},
	}
	for _, c := range cases {
		rec, ok := reg[c.id]
		if ok != c.found {
			t.Errorf("lookup %q: found=%v, want %v", c.id, ok, c.found)
		}
		if ok && rec.id != c.id {
			t.Errorf("lookup %q: record has id %q (map key and id disagree)", c.id, rec.id)
		}
	}
}

func TestAuthenticateClient(t *testing.T) {
	env := loadDotEnv(t)
	reg := newClientRegistry()

	cases := []struct {
		name   string
		client string
		secret string
		ok     bool
	}{
		{"client1 correct secret", "client1", env["SECRET1"], true},
		{"client2 correct secret", "client2", env["SECRET2"], true},
		{"client3 correct secret", "client3", env["SECRET3"], true},
		{"client2 wrong secret", "client2", "wrong", false},
		{"client2 empty secret", "client2", "", false},
		{"client2 with client1's secret", "client2", env["SECRET1"], false},
		{"client3 with client2's secret", "client3", env["SECRET2"], false},
		{"client2 secret sent as its hash", "client2", env["SECRET2_HASH"], false},
		{"unknown id", "client4", "wrong", false},
		{"unknown id with a valid secret", "client4", env["SECRET2"], false},
		{"id wrong case", "CLIENT2", env["SECRET2"], false},
		{"empty id", "", env["SECRET2"], false},
		{"empty id and secret", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, ok := authenticateClient(reg, c.client, c.secret)
			if ok != c.ok {
				t.Fatalf("ok=%v, want %v", ok, c.ok)
			}
			if ok && (rec == nil || rec.id != c.client) {
				t.Errorf("returned wrong record: %+v", rec)
			}
			if !ok && rec != nil {
				t.Errorf("returned a record on failure: %+v", rec)
			}
		})
	}
}

func TestRegistryGrantTypes(t *testing.T) {
	loadDotEnv(t)
	reg := newClientRegistry()

	cases := []struct {
		client, grant string
		allowed       bool
	}{
		{"client1", "authorization_code", true},
		{"client1", "client_credentials", false}, // → unauthorized_client
		{"client2", "client_credentials", true},
		{"client2", "authorization_code", false},
		{"client3", "client_credentials", true},
		{"client2", "password", false}, // → unsupported_grant_type
		{"client2", "Client_Credentials", false},
	}
	for _, c := range cases {
		if got := reg[c.client].allowedGrantTypes[c.grant]; got != c.allowed {
			t.Errorf("%s / %q: allowed=%v, want %v", c.client, c.grant, got, c.allowed)
		}
	}
}

func TestRegistryScopes(t *testing.T) {
	loadDotEnv(t)
	reg := newClientRegistry()

	// Each requested scope list must be fully allowed (reject, don't narrow).
	cases := []struct {
		client, scope string
		allowed       bool
	}{
		{"client2", "notes:read", true},
		{"client2", "notes:write", false}, // → invalid_scope
		{"client2", "NOTES:READ", false},  // scopes are case-sensitive
		{"client2", "metrics:read", false},
		{"client3", "notes:read", true},
		{"client3", "notes:read notes:write", true},
		{"client3", "notes:read notes:write metrics:read", true},
		{"client3", "notes:read notes:delete", false}, // one bad scope fails the lot
		{"client3", "metrics:write", false},
		{"client1", "notes:read notes:write", true},
	}
	for _, c := range cases {
		rec := reg[c.client]
		got := true
		for _, s := range strings.Split(c.scope, " ") {
			if !rec.allowedScopes[s] {
				got = false
			}
		}
		if got != c.allowed {
			t.Errorf("%s / %q: allowed=%v, want %v", c.client, c.scope, got, c.allowed)
		}
	}
}
