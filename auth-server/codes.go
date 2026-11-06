package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// AuthCode is what the server remembers about an authorization code. Everything
// here is checked again when the code is exchanged at /token, so a code is only
// useful to the right client, at the right redirect URI, with the right PKCE
// verifier, once, and only briefly.
type AuthCode struct {
	ClientID    string   `json:"client_id"`
	UserID      string   `json:"user_id"`      // the user who logged in and consented
	RedirectURI string   `json:"redirect_uri"` // must be sent again, identically, at /token (§4.1.3)
	Scope       []string `json:"scope"`
	Challenge   string   `json:"challenge"` // PKCE code_challenge (S256), checked against the verifier
}

// CodeStore keeps authorization codes in Redis under "code:<SHA-256 of the
// code>", so a dump of Redis contains no usable codes. Redis does the two
// hard parts itself: the key's TTL expires the code, and GETDEL makes it
// single use (§4.1.2).
type CodeStore struct {
	rdb *redis.Client
}

func codeKey(code string) string { return "code:" + hashSecret(code) }

// issue creates a random authorization code, saves its record and returns it.
func (s *CodeStore) issue(ctx context.Context, rec AuthCode, ttl time.Duration) (string, error) {
	code := generateSecret()
	b, _ := json.Marshal(rec)
	if err := s.rdb.Set(ctx, codeKey(code), b, ttl).Err(); err != nil {
		return "", err
	}
	return code, nil
}

// redeem returns a code's record and deletes it in one atomic step, so even
// two requests arriving together can't both exchange it. A nil record means
// the code is unknown, expired (Redis already removed it) or already used.
func (s *CodeStore) redeem(ctx context.Context, code string) (*AuthCode, error) {
	b, err := s.rdb.GetDel(ctx, codeKey(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec AuthCode
	err = json.Unmarshal(b, &rec)
	return &rec, err
}
