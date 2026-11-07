package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

// Sessions live in Redis, so they survive restarts and several copies of the
// app can share them. The browser only ever holds a random session ID in a
// cookie, and Redis keys use its SHA-256, so a dump of Redis can't be used to
// take over anyone's session. Two kinds of record hang off each session:
//
//	login:<hash>  the state and PKCE verifier between /login and /callback
//	token:<hash>  the access and refresh tokens, once logged in (never sent to the browser)

// loginTTL is how long a user has to finish logging in at the auth server.
const loginTTL = 10 * time.Minute

// pendingLogin is what /login remembers for /callback.
type pendingLogin struct {
	State    string `json:"state"`    // CSRF protection for /callback
	Verifier string `json:"verifier"` // PKCE code_verifier; never leaves this server
}

// sessionID returns the browser's session ID, creating one (and its cookie)
// if it doesn't have one yet.
func sessionID(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("session"); err == nil && c.Value != "" {
		return c.Value
	}
	id := rand.Text()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,                 // page scripts can't read it
		SameSite: http.SameSiteLaxMode, // sent on the redirect back from the auth server, not on cross-site POSTs
	})
	return id
}

func sessionKey(kind, id string) string {
	sum := sha256.Sum256([]byte(id))
	return kind + ":" + hex.EncodeToString(sum[:])
}

func (a *app) saveLogin(ctx context.Context, id string, l pendingLogin) error {
	b, _ := json.Marshal(l)
	return a.rdb.Set(ctx, sessionKey("login", id), b, loginTTL).Err()
}

// takeLogin returns the pending login and deletes it in one atomic step, so
// a state and verifier can be used only once, even by two simultaneous
// callbacks. ok is false if there's no login in progress.
func (a *app) takeLogin(ctx context.Context, id string) (l pendingLogin, ok bool, err error) {
	b, err := a.rdb.GetDel(ctx, sessionKey("login", id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return l, false, nil
	}
	if err != nil {
		return l, false, err
	}
	return l, json.Unmarshal(b, &l) == nil, nil
}

// tokenOf returns the session's access token, or nil if not logged in.
func (a *app) tokenOf(ctx context.Context, id string) (*oauth2.Token, error) {
	b, err := a.rdb.Get(ctx, sessionKey("token", id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tok oauth2.Token
	if err := json.Unmarshal(b, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

// sessionTTL matches the auth server's login lifetime: after that, the refresh
// token stops working, so there's no point keeping it.
const sessionTTL = 24 * time.Hour

// saveToken keeps the tokens for as long as they can be used: the whole login
// when there's a refresh token, otherwise until the access token expires.
func (a *app) saveToken(ctx context.Context, id string, tok *oauth2.Token) error {
	ttl := time.Until(tok.Expiry)
	if tok.RefreshToken != "" {
		ttl = sessionTTL
	} else if tok.Expiry.IsZero() || ttl <= 0 {
		ttl = time.Hour
	}
	b, _ := json.Marshal(tok)
	return a.rdb.Set(ctx, sessionKey("token", id), b, ttl).Err()
}

func (a *app) forgetToken(ctx context.Context, id string) error {
	return a.rdb.Del(ctx, sessionKey("token", id)).Err()
}
