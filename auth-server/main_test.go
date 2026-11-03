package main

import (
	"log"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

// TestMain loads .env once before any test runs. newClientRegistry needs the
// SECRETn_HASH values, and tests log in as each client with SECRETn.
func TestMain(m *testing.M) {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("tests need .env: %v", err)
	}
	os.Exit(m.Run())
}
