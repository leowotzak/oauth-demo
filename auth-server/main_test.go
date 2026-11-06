package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/joho/godotenv"
)

// testRedis is an in-process fake Redis shared by every test, so go test
// needs no real Redis running.
var testRedis *miniredis.Miniredis

// TestMain loads .env once before any test runs (newClientRegistry needs the
// SECRETn_HASH values, and tests log in as each client with SECRETn), and
// points REDIS_URL at the fake Redis.
func TestMain(m *testing.M) {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("tests need .env: %v", err)
	}
	var err error
	if testRedis, err = miniredis.Run(); err != nil {
		log.Fatal(err)
	}
	os.Setenv("REDIS_URL", "redis://"+testRedis.Addr())
	code := m.Run()
	testRedis.Close()
	os.Exit(code)
}

// codeCount is how many authorization codes are stored right now. Tests that
// use it call testRedis.FlushAll() first.
func codeCount() int {
	n := 0
	for _, k := range testRedis.Keys() {
		if strings.HasPrefix(k, "code:") {
			n++
		}
	}
	return n
}

// storedCode reads a code's record straight from Redis.
func storedCode(t *testing.T, code string) *AuthCode {
	t.Helper()
	raw, err := testRedis.Get(codeKey(code))
	if err != nil {
		return nil
	}
	var rec AuthCode
	if json.Unmarshal([]byte(raw), &rec) != nil {
		t.Fatalf("bad record %q", raw)
	}
	return &rec
}
