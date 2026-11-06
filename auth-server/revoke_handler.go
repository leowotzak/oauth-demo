package main

import (
	"log"
	"net/http"
	"time"
)

// revokedKey is where a revoked token's ID (jti) is kept. Resource servers
// check it after verifying a token's signature.
func revokedKey(jti string) string { return "revoked:" + jti }

// handleRevoke implements POST /revoke (RFC 7009) for access tokens. A JWT
// stays valid until it expires, so revoking one means adding its ID to a deny
// list in Redis. The entry expires when the token would have anyway, so the
// list never grows.
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
	claims, ok := s.parseAccessToken(token)
	ttl := time.Until(time.Unix(claims.Expires, 0))
	if ok && claims.ClientID == client.id && ttl > 0 {
		if err := s.rdb.Set(r.Context(), revokedKey(claims.ID), 1, ttl).Err(); err != nil {
			log.Printf("revoking token: %v", err)
			writeError(w, http.StatusServiceUnavailable, errTemporarilyUnavailable, "try again shortly")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}
