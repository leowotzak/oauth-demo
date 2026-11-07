# auth-server

The authorization server, written by hand from [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) (PKCE) and [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) (JWT access tokens), with no OAuth or JWT libraries. It holds the users and clients, runs the login page, issues signed access tokens, and revokes them. Authorization codes and revoked token IDs live in Redis. See the [project README](../README.md) for the demo accounts and how it fits with the other modules.

```sh
go run .          # http://localhost:8080 (needs Redis: docker compose up -d redis)
go test ./...     # uses an in-process fake Redis
./test-curl.sh    # client credentials checks against the running server
```

`.env` holds the client secrets, user passwords and their hashes, the token signing key, and `REDIS_URL` (tutorial only). The bcrypt hashes are single-quoted because they contain `$`.

## Endpoints

| Endpoint | Used by | Does |
|---|---|---|
| `GET /authorize` | The user's browser | Validates the request, shows the login and consent page |
| `POST /authorize` | The login page | Checks the password, then redirects back with a code (or an error) |
| `POST /token` | Clients | Issues tokens for `client_credentials`, `authorization_code` and `refresh_token` |
| `POST /revoke` | Clients | Revokes one of the client's own access or refresh tokens (RFC 7009) |
| `GET /.well-known/jwks.json` | Resource servers | Publishes the public key that checks token signatures |

### `GET` and `POST /authorize`
Checks run in two phases (§4.1.2.1):
1. **Can it safely redirect back?** An unknown `client_id` or an unregistered `redirect_uri` (exact match only) gets a plain 400 page, **never a redirect**, so the server can't be used as an open redirector.
2. **Everything else** goes back to the client as `redirect_uri?error=…&state=…`: `unsupported_response_type`, `unauthorized_client`, `invalid_scope`, or `invalid_request` when PKCE is missing or isn't `S256`.

`POST` runs the same checks again on the submitted form, because the hidden fields can be edited. Then:
- **Deny** → `error=access_denied`.
- **Wrong username or password** → the page again with an error, and no redirect.
- **Allow** → `redirect_uri?code=…&state=…`. The code is valid for one minute and records the client, user, redirect URI, scope and PKCE challenge.

The page sets `X-Frame-Options: DENY` (clickjacking), and `html/template` escapes every value from the request.

### `POST /token`
Parameters come from the form body only. Client authentication is HTTP Basic, or `client_id`/`client_secret` in the body.

| Check | Error |
|---|---|
| Client authentication fails | `invalid_client` (401) |
| `grant_type` missing / not supported / not allowed for this client | `invalid_request` / `unsupported_grant_type` / `unauthorized_client` |
| **Client credentials:** a requested scope isn't allowed (omitted → the client's defaults) | `invalid_scope` |
| **Authorization code:** `code` missing | `invalid_request` |
| **Authorization code:** code unknown, expired or used; issued to another client; different `redirect_uri`; or `SHA256(code_verifier)` doesn't match the challenge | `invalid_grant` |
| **Refresh:** `refresh_token` missing | `invalid_request` |
| **Refresh:** token unknown, expired, already used (which also revokes the login) or issued to another client | `invalid_grant` |
| **Refresh:** a scope that wasn't part of the original approval | `invalid_scope` |

For the authorization code grant, the token gets the scope the user approved and records the user; any `scope` parameter is ignored. Codes are stored in Redis as `code:<hash>` with a one-minute TTL, and redeemed with `GETDEL`, which reads and deletes in one atomic step: a code works once, even if two requests arrive together, and even a failed attempt burns it. Responses carry `Cache-Control: no-store`. Only logins get a refresh token: the code exchange and each refresh, for clients allowed the `refresh_token` grant (`client1`). Client credentials never does (§4.4.3), since the client can simply authenticate again.

### Access tokens (`jwt.go`)
Each access token is a JWT signed with the server's Ed25519 key (`alg: EdDSA`, `typ: at+jwt`, `kid: key-1`):
```json
{"iss":"http://localhost:8080", "sub":"user-1", "aud":"notes-api", "client_id":"client1",
 "scope":"notes:read", "iat":…, "exp":…, "jti":"<random>"}
```
`sub` is left out for client credentials. The payload is signed, not encrypted, so it holds nothing secret. The public key is published at `/.well-known/jwks.json` (RFC 7517 and 8037), and it can check tokens but not make them.

The server stores no access tokens, and a valid signature can't be undone, so they last only **15 minutes**. Refresh tokens cover longer logins.

### Refresh tokens (`refresh.go`)
A refresh token is a random 256-bit value that lets a client get a new access token without the user logging in again (§6). Each login starts a **family**, and three rules make stolen refresh tokens short-lived:

- **Rotation.** Every refresh returns a **new** refresh token and destroys the old one (`GETDEL`), so each one works exactly once.
- **Reuse detection** (RFC 9700 §4.14). A rotated-out token is remembered as `refresh-used:<hash>`. If it ever comes back, someone has a copy: the server **revokes the whole family**, deleting its current refresh token and putting its latest access token on the deny list. Whichever of the thief or the real client refreshes second triggers this, and both are logged out.
- **An absolute lifetime.** A family lasts **24 hours** from the login, and every rotated token gets only the time left, so refreshing can't keep a login alive forever.

A refresh can ask for **less** scope than was approved, but never more; the new refresh token always keeps the full approved scope (§6).

| Redis key | Holds | Expires |
|---|---|---|
| `refresh:<hash>` | The family's live refresh token: client, user, scope, family ID | End of the family |
| `refresh-used:<hash>` | A rotated-out token → its family ID, to recognise reuse | End of the family |
| `family:<id>` | The live token's hash and the latest access token's `jti`, so the family can be revoked | End of the family |

### `POST /revoke` (`revoke_handler.go`)
A client authenticates and sends `token=<access or refresh token>`. **A refresh token** revokes its whole family, which is what logging out does. **An access token**, if it's genuine, unexpired and **issued to that client**, is revoked on its own: its `jti` goes into Redis as `revoked:<jti>`, with a TTL that ends when the token would have expired anyway, so the deny list never grows. Resource servers check that key. Anything else (an unknown token, another client's token, an expired one) needs no action and still gets 200 OK (§2.2), so the caller learns nothing and retrying is always safe.

If Redis is down, logins, code exchanges, refreshes and revocations return 503 rather than continuing without their checks.

## Left out to keep the demo simple
- Rejecting repeated parameters, rejecting Basic and body credentials together, and URL-decoding Basic credentials (§2.3.1)
- Validating client configuration at startup, and timing padding for unknown client IDs
- A CSRF token on the login form, and a login session (users log in every time)
- Revoking tokens issued from a code when someone reuses it (§4.1.2)
- Rotating the signing key (there's one fixed key, `key-1`)
