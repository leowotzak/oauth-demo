package main

import (
	"context"
	"log"
	"net/http"
	"time"
)

// revokedKey is where a revoked token's ID (jti) is kept. Resource servers
// check it after verifying a token's signature.
func revokedKey(jti string) string { return "revoked:" + jti }

// handleRevoke implements POST /revoke (RFC 7009) for access and refresh
// tokens. A JWT stays valid until it expires, so revoking an access token
// means adding its ID to a deny list in Redis; the entry expires when the
// token would have anyway, so the list never grows. Revoking a refresh token
// revokes its whole family (the login), including its latest access token.
func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	// 1. The caller must authenticate (§2.1), and may only revoke its own tokens.
	client, ok := s.authenticateCaller(w, r)
	if !ok {
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "missing token")
		return
	}

	// 2. Revoke it if it's a real token of ours, issued to this client, and not
	//    yet expired. Anything else needs no action, and still gets 200 OK
	//    (§2.2): the caller learns nothing, and retrying is always safe.
	if err := s.revoke(r.Context(), client, token); err != nil {
		log.Printf("revoking token: %v", err)
		writeError(w, http.StatusServiceUnavailable, errTemporarilyUnavailable, "try again shortly")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// revoke handles either kind of token. The token_type_hint parameter is
// optional (§2.1), so this simply tries both: a signed access token, then a
// live refresh token.
func (s *server) revoke(ctx context.Context, client *ClientRecord, token string) error {
	if claims, ok := s.parseAccessToken(token); ok {
		ttl := time.Until(time.Unix(claims.Expires, 0))
		if claims.ClientID != client.id || ttl <= 0 {
			return nil
		}
		return s.rdb.Set(ctx, revokedKey(claims.ID), 1, ttl).Err()
	}
	rec, err := s.lookupRefresh(ctx, token)
	if err != nil || rec == nil || rec.ClientID != client.id {
		return err
	}
	return s.revokeFamily(ctx, rec.Family)
}
