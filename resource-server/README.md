# resource-server

A notes API protected by access tokens from [`auth-server`](../auth-server): the **resource server** in OAuth terms. It never sees passwords or client secrets, only the Bearer tokens clients send it. See the [project README](../README.md) for how it fits with the other modules.

```sh
go run .          # http://localhost:8081 (needs auth-server and Redis running)
go test ./...     # uses a fake auth server and an in-process fake Redis
./test-curl.sh    # both flows end to end, with auth-server and resource-server running
```

| Endpoint | Needs scope |
|---|---|
| `GET /notes` → `{"owner": "user-1", "notes": [...]}` | `notes:read` |
| `POST /notes` with body `{"text": "..."}` | `notes:write` |

## How a request is checked

`requireScope` in `auth.go` runs before every handler ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)):

1. **Read the token** from `Authorization: Bearer <token>`. Missing → 401.
2. **Check the JWT locally**, in this order:
   - the header must say `alg: EdDSA` and `typ: at+jwt`. Only one algorithm is allowed, which blocks `alg: none` and algorithm confusion attacks.
   - the signature must verify with the auth server's public key for that `kid`. The key is fetched from `/.well-known/jwks.json` on first use and cached.
   - only then are the claims trusted: `iss` must be the auth server, `aud` must be `notes-api`, and `exp` must not have passed (with 30 seconds of clock skew allowed).

   Any failure → 401 `invalid_token`. If the keys can't be fetched at all → 503 (fail closed).
3. **Check it hasn't been revoked:** is `revoked:<jti>` in Redis (put there by the auth server's `/revoke`)? Revoked → 401 `invalid_token`. Redis unreachable → 503: fail closed, so a revoked token can never slip through.
4. **Check the scope** the endpoint needs. Missing → 403 `insufficient_scope`.
5. **Work out the owner** and pass it to the handler: the token's `sub` (its user), or `client:<id>` for client credentials tokens, which have no user.

Error codes go in the `WWW-Authenticate: Bearer` header (§3). A 401 means "get a valid token"; a 403 means "your valid token doesn't allow this". The note handlers in `notes.go` contain no OAuth code. Notes are Redis lists (`notes:<owner>`), so alice and bob see only their own, and notes survive restarts. alice and bob get their starting note only if they have none yet.

## Design choices
- **No call to the auth server per request.** After fetching the public key once, the API checks tokens itself, so it's faster and keeps working if the auth server is down.
- **One Redis lookup per request** for revocation. That's the classic compromise: JWTs removed the network hop to the auth server, and the deny list brings back a much cheaper one to Redis, in exchange for revocation that takes effect immediately.
- **An unknown `kid` triggers a new key fetch**, which is how a rotated key would be picked up. A real service would limit how often that happens, so junk tokens can't make it fetch on every request.
- **Tokens without a user get their own notes**, owned by the client. The stricter alternative is to reject them on endpoints about "my" data.
- **The `Bearer` prefix is matched case-sensitively**, although HTTP says scheme names are case-insensitive.
