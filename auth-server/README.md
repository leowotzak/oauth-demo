# auth-server

The authorization server, written by hand from [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) (PKCE) and [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) (introspection), with no OAuth libraries. It holds the users and clients, runs the login page, and issues and checks tokens. See the [project README](../README.md) for how it fits with the other modules, and for the demo accounts.

```sh
go run .          # http://localhost:8080
go test ./...
./test-curl.sh    # client credentials checks against the running server
```

## Endpoints

| Endpoint | Used by | Does |
|---|---|---|
| `GET /authorize` | The user's browser | Validates the request, shows the login and consent page |
| `POST /authorize` | The login page | Checks the password, then redirects back with a code (or an error) |
| `POST /token` | Clients | Issues tokens for `client_credentials` and `authorization_code` |
| `POST /introspect` | Resource servers | Says whether a token is active, and what it allows |

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

For the authorization code grant, the token gets the scope the user approved and records the user; any `scope` parameter is ignored. Checking a code marks it used, so even a failed attempt burns it. Responses carry `Cache-Control: no-store`, and never a refresh token.

### `POST /introspect`
The caller authenticates as a client. A missing `token` is `invalid_request`. An active token returns `active`, `scope`, `client_id`, `sub` (the user; left out for client credentials), `token_type` and `exp`. An unknown or expired token returns only `{"active":false}`, so the caller learns nothing about why.

## Files

| File | Contents |
|---|---|
| `main.go` | The `server` struct, routes and startup |
| `clients.go` | Client registry, client authentication, redirect URI and scope checks |
| `users.go` | Demo users and password checks (bcrypt) |
| `authorize_handler.go`, `templates/authorize.html` | `/authorize` and the login and consent page |
| `token_handler.go` | `/token`, including the code exchange and PKCE check |
| `introspect_handler.go` | `/introspect` |
| `codes.go`, `tokens.go` | Authorization code and access token stores |
| `secrets.go` | Random secret generation and SHA-256 hashing |
| `errors.go` | OAuth error responses |
| `.env` | Client secrets, user passwords and their hashes (tutorial only). The bcrypt hashes are single-quoted because they contain `$`. |

## Storage
- **Client secrets, tokens and codes** are 256 random bits, stored only as SHA-256 hashes and compared in constant time.
- **User passwords** are bcrypt hashes, because people choose guessable passwords.
- **Tokens** last one hour; **codes**, one minute. Both stores are in memory, behind a mutex.

## Left out to keep the demo simple
- Rejecting repeated parameters, rejecting Basic and body credentials together, and URL-decoding Basic credentials (§2.3.1)
- Validating client configuration at startup, and timing padding for unknown client IDs
- A CSRF token on the login form, and a login session (users log in every time)
- Revoking tokens issued from a code when someone reuses it (§4.1.2)
- Restricting `/introspect` to resource servers (any client may call it)
