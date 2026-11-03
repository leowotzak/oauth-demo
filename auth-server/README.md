# auth-server

A hand-written OAuth 2.0 authorization server in Go, built to learn the protocol. It uses only the standard library. No OAuth libraries.

So far it implements the **client credentials grant** ([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)): a machine client authenticates at `POST /token` and receives an access token.

> **Tutorial only.** Plaintext client secrets are stored in `.env`, the server uses plain HTTP, and tokens are kept in memory. None of this is suitable for production.

## Running it

```sh
set -a; source .env; set +a   # load the client secret hashes
go run .                      # listens on http://localhost:8080

curl -u "client2:$SECRET2" -d grant_type=client_credentials localhost:8080/token
# {"access_token":"…","token_type":"Bearer","expires_in":3600,"scope":"notes:read"}

go test ./...                 # tests read .env themselves
./test-curl.sh                # curl suite against the running server
```

## Files

| File | Contents |
|---|---|
| `main.go` | The `server` struct, routing and startup |
| `clients.go` | Client registry and `authenticateClient` |
| `secrets.go` | Generating random secrets and hashing them |
| `tokens.go` | The access token store |
| `token_handler.go` | The `POST /token` handler |
| `errors.go` | OAuth error responses |
| `.env` | Client secrets and hashes (tutorial only, never commit it) |

## How it was built

### 1. Client registry
Every client has an ID, a secret hash, allowed grant types, allowed scopes and default scopes.

| Client | Grant | Allowed scopes | Default | Used to test |
|---|---|---|---|---|
| `client1` | `authorization_code` | `notes:read notes:write` | `notes:read` | `unauthorized_client` |
| `client2` | `client_credentials` | `notes:read` | `notes:read` | The basic success case |
| `client3` | `client_credentials` | `notes:read notes:write metrics:read` | `notes:read` | Requests with several scopes |

- Scopes use `resource:action` names and are case-sensitive (§3.3). They limit what the **client** can do, not what the user can do.
- Default scopes are narrower than the allowed ones, so a client has to ask explicitly for its more powerful scopes.
- The constructor doesn't validate its input, to keep the code short. A real server would reject bad configuration at startup.

### 2. Client secrets
- Secrets are 256 random bits from `crypto/rand`, encoded as base64url. §10.10 requires at least 128 bits, and base64url needs no escaping in headers or form bodies.
- Only the SHA-256 hash is stored. A fast hash is fine because the secrets are long and random; bcrypt is for human passwords.

### 3. Client authentication
`authenticateClient` hashes the secret a client sends and compares it with `subtle.ConstantTimeCompare`. An unknown ID and a wrong secret return the same failure, and an unknown ID is compared against a dummy hash so the timing doesn't reveal which IDs exist.

### 4. Token store
- Tokens are opaque random strings. No JWTs yet, so no signing keys are needed.
- Each token has a client ID, the granted scopes and an expiry time (1 hour).
- Tokens are stored under their SHA-256 hash, so a dump of the store contains no working tokens.
- The store is protected by a mutex because requests run concurrently.

### 5. `POST /token`
The checks run in a fixed order, and each kind of failure has its own error (§5.2):

1. **Request format:** the body must be form-encoded and is read from the body only (query strings are ignored). Repeated parameters are rejected. Failures return `invalid_request`.
2. **Client authentication:** Basic auth (URL-decoded, per §2.3.1) or `client_id`/`client_secret` in the body, but not both. Failures return `invalid_client` with status 401.
3. **Grant type:** a missing one returns `invalid_request`, an unknown one `unsupported_grant_type`, and one the client isn't allowed `unauthorized_client`.
4. **Scope:** an omitted scope uses the client's defaults. Duplicates are removed. Empty entries or any scope the client isn't allowed reject the whole request with `invalid_scope`; it isn't silently narrowed.
5. **Issue the token:** the response includes `scope` and no refresh token (§4.4.3). Every response has `Cache-Control: no-store`.

## Next steps
1. A resource server that accepts these tokens as `Authorization: Bearer` (RFC 6750)
2. The authorization code flow: users, login, consent and redirects
3. PKCE (RFC 7636)
4. Refresh tokens with rotation
5. Introspection, revocation and metadata endpoints
6. JWT access tokens (optional)
