package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Refresh tokens (RFC 6749 §6) with rotation and reuse detection (RFC 9700
// §4.14). Every login through the authorization code flow starts a "family":
// a chain of refresh tokens where each use replaces the token with a new one.
// If a token that was already replaced is ever presented again, someone has a
// copy, so the whole family is revoked.
//
// Redis keys, all expiring when the family does:
//
//	refresh:<hash>       the family's one live refresh token
//	refresh-used:<hash>  a token that was rotated out → its family ID (to spot reuse)
//	family:<id>          the family: its live token, and its latest access token

// RefreshToken is what the server remembers about a refresh token.
type RefreshToken struct {
	ClientID      string   `json:"client_id"`
	UserID        string   `json:"user_id"`
	Scope         []string `json:"scope"`          // what the user approved; never changes within a family (§6)
	Family        string   `json:"family"`         // ID of the chain this token belongs to
	FamilyExpires int64    `json:"family_expires"` // absolute end of the login: rotation can't extend it
}

// family tracks a chain's current state, so the whole chain can be revoked.
type family struct {
	Current   string `json:"current"`    // hash of the live refresh token
	AccessJTI string `json:"access_jti"` // ID of the latest access token issued in this family
	AccessExp int64  `json:"access_exp"` // and when it expires
}

func refreshKey(token string) string { return "refresh:" + hashSecret(token) }
func usedKey(token string) string    { return "refresh-used:" + hashSecret(token) }
func familyKey(id string) string     { return "family:" + id }

// errReuse means an already-rotated refresh token came back: its family has
// been revoked.
var errReuse = errors.New("refresh token reused")

// startFamily is called when a login completes (the code exchange): it creates
// a new family and its first refresh token.
func (s *server) startFamily(ctx context.Context, clientID, userID string, scope []string, accessToken string) (string, error) {
	rec := RefreshToken{
		ClientID:      clientID,
		UserID:        userID,
		Scope:         scope,
		Family:        generateSecret(),
		FamilyExpires: s.now().Add(s.refreshTTL).Unix(),
	}
	return s.storeRefresh(ctx, rec, "", accessToken)
}

// redeemRefresh takes a refresh token out of Redis. GETDEL makes it single
// use: of two requests with the same token, only one gets it. If the token
// isn't live but was rotated out earlier, that's reuse, so the family is
// revoked and errReuse returned. A nil record means unknown or expired.
func (s *server) redeemRefresh(ctx context.Context, token string) (*RefreshToken, error) {
	b, err := s.rdb.GetDel(ctx, refreshKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		familyID, err := s.rdb.Get(ctx, usedKey(token)).Result()
		if errors.Is(err, redis.Nil) {
			return nil, nil // never issued, or the family already ended
		}
		if err != nil {
			return nil, err
		}
		if err := s.revokeFamily(ctx, familyID); err != nil {
			return nil, err
		}
		return nil, errReuse
	}
	if err != nil {
		return nil, err
	}
	var rec RefreshToken
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// rotate replaces a redeemed refresh token with a new one in the same family,
// and remembers the old one so that presenting it again is caught as reuse.
func (s *server) rotate(ctx context.Context, old string, rec RefreshToken, accessToken string) (string, error) {
	return s.storeRefresh(ctx, rec, old, accessToken)
}

// storeRefresh saves a new refresh token for rec's family and makes it the
// family's live token. If old is set, it's marked as rotated out. All writes
// happen in one Redis transaction, and expire when the family does.
func (s *server) storeRefresh(ctx context.Context, rec RefreshToken, old, accessToken string) (string, error) {
	ttl := time.Unix(rec.FamilyExpires, 0).Sub(s.now()) // what's left of the login, not a fresh 24 hours
	token := generateSecret()
	claims, _ := s.parseAccessToken(accessToken)
	recJSON, _ := json.Marshal(rec)
	famJSON, _ := json.Marshal(family{Current: hashSecret(token), AccessJTI: claims.ID, AccessExp: claims.Expires})

	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, refreshKey(token), recJSON, ttl)
		p.Set(ctx, familyKey(rec.Family), famJSON, ttl)
		if old != "" {
			p.Set(ctx, usedKey(old), rec.Family, ttl)
		}
		return nil
	})
	return token, err
}

// revokeFamily ends a login everywhere: it deletes the family's live refresh
// token and puts its latest access token on the deny list, so neither the
// thief nor the real client can keep using the chain.
func (s *server) revokeFamily(ctx context.Context, familyID string) error {
	b, err := s.rdb.GetDel(ctx, familyKey(familyID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil // already revoked or expired
	}
	if err != nil {
		return err
	}
	var f family
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Del(ctx, "refresh:"+f.Current)
		if ttl := time.Until(time.Unix(f.AccessExp, 0)); ttl > 0 && f.AccessJTI != "" {
			p.Set(ctx, revokedKey(f.AccessJTI), 1, ttl)
		}
		return nil
	})
	return err
}

// lookupRefresh reads a live refresh token without using it up (for /revoke).
func (s *server) lookupRefresh(ctx context.Context, token string) (*RefreshToken, error) {
	b, err := s.rdb.Get(ctx, refreshKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec RefreshToken
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}
