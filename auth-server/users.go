package main

import "golang.org/x/crypto/bcrypt"

// User is a person who can log in on the authorization page and grant a
// client access. Users only exist in the authorization code flow; client
// credentials has no user.
type User struct {
	id           string // stable ID; goes into tokens as the user ("sub")
	passwordHash []byte // bcrypt, never the plaintext
}

// newUserRegistry returns the demo users, keyed by username.
// The password hashes come from .env.
func newUserRegistry() map[string]*User {
	return map[string]*User{
		"alice": {id: "user-1", passwordHash: []byte(mustGetenv("ALICE_PASSWORD_HASH"))},
		"bob":   {id: "user-2", passwordHash: []byte(mustGetenv("BOB_PASSWORD_HASH"))},
	}
}

// authenticateUser checks a username and password. Passwords use bcrypt,
// not SHA-256 like client secrets: people choose guessable passwords, so the
// hash must be slow and salted to make guessing expensive.
func authenticateUser(users map[string]*User, username, password string) (*User, bool) {
	u, ok := users[username]
	if !ok || bcrypt.CompareHashAndPassword(u.passwordHash, []byte(password)) != nil {
		return nil, false
	}
	return u, true
}
