# auth-server

A hand-written OAuth 2.0 authorization server in Go, built to learn the protocol. No OAuth libraries: the dependencies are [godotenv](https://github.com/joho/godotenv), for loading `.env`, and `golang.org/x/crypto/bcrypt`, for user passwords.

It implements two grants:
- **Client credentials** ([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)): a machine client authenticates at `POST /token` and receives an access token.
- **Authorization code with PKCE** ([§4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)): a user logs in at `/authorize` and approves a client, which exchanges the resulting code at `POST /token`.

Resource servers, such as [`resource-server`](../resource-server), check tokens at `POST /introspect` ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)).

> **Tutorial only.** Plaintext client secrets are stored in `.env`, the server uses plain HTTP, and tokens are kept in memory. None of this is suitable for production.

## Running it

```sh
go run .                      # loads .env, listens on http://localhost:8080

curl -u "client2:$SECRET2" -d grant_type=client_credentials localhost:8080/token
# {"access_token":"…","token_type":"Bearer","expires_in":3600,"scope":"notes:read"}

go test ./...                 # tests read .env themselves
./test-curl.sh                # curl suite against the running server
```

## Files

| File | Contents |
|---|---|
| `main.go` | The `server` struct, routing and startup |
| `clients.go` | Client registry, `authenticateClient` and redirect URI checks |
| `users.go` | Demo users and `authenticateUser` (for the authorization code flow) |
| `secrets.go` | Generating random secrets and hashing them |
| `tokens.go` | The access token store |
| `token_handler.go` | The `POST /token` handler |
| `introspect_handler.go` | The `POST /introspect` handler |
| `authorize_handler.go`, `templates/authorize.html` | `GET`/`POST /authorize` and the login and consent page |
| `codes.go` | The authorization code store |
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
| `notes-api` | none | none | none | The resource server. It can call `/introspect` but can't get tokens |

- Scopes use `resource:action` names and are case-sensitive (§3.3). They limit what the **client** can do, not what the user can do.
- Default scopes are narrower than the allowed ones, so a client has to ask explicitly for its more powerful scopes.
- The registry is a plain map literal with no validation, to keep the code short. A real server would reject bad configuration at startup.

### 2. Client secrets
- Secrets are 256 random bits from `crypto/rand`, encoded as base64url. §10.10 requires at least 128 bits, and base64url needs no escaping in headers or form bodies.
- Only the SHA-256 hash is stored. A fast hash is fine because the secrets are long and random; bcrypt is for human passwords.

### 3. Client authentication
`authenticateClient` hashes the secret a client sends and compares it with `subtle.ConstantTimeCompare`. An unknown ID and a wrong secret return the same failure.

### 4. Token store
- Tokens are opaque random strings. No JWTs yet, so no signing keys are needed.
- Each token has a client ID, the granted scopes and an expiry time (1 hour).
- Tokens are stored under their SHA-256 hash, so a dump of the store contains no working tokens.
- The store is protected by a mutex because requests run concurrently.

### 5. `POST /token`
Parameters are read from the form-encoded body only; the query string is ignored. The checks run in order, and each kind of failure has its own error (§5.2):

1. **Client authentication:** Basic auth, or `client_id`/`client_secret` in the body. Failures return `invalid_client` with status 401.
2. **Grant type:** a missing one returns `invalid_request`, anything other than `client_credentials` returns `unsupported_grant_type`, and a client that isn't allowed it gets `unauthorized_client`.
3. **Scope:** an omitted scope uses the client's defaults. Any scope the client isn't allowed rejects the whole request with `invalid_scope`; it isn't silently narrowed.
4. **Issue the token:** the response includes `scope` and no refresh token (§4.4.3). Every response has `Cache-Control: no-store`.

Left out to keep the demo simple: rejecting repeated parameters, rejecting Basic and body credentials together, and URL-decoding Basic credentials (§2.3.1).

### 6. `POST /introspect`
Resource servers send `token=<access token>` and get back whether it's usable (RFC 7662):

1. **The caller must authenticate** as a registered client, or anyone could probe tokens. Any client may call it here; a real server would allow only resource servers.
2. **A missing `token`** returns `invalid_request`.
3. **An active token** returns `{"active":true,"scope":…,"client_id":…,"token_type":"Bearer","exp":…}`.
4. **An unknown or expired token** returns just `{"active":false}` with 200 OK, so the caller learns nothing about why.

### 7. Groundwork for the authorization code flow
- **Users:** `alice` and `bob`, who will log in on the authorization page. Their passwords are stored as **bcrypt** hashes, not SHA-256: people choose guessable passwords, so the hash must be slow and salted. (In `.env`, the hashes are single-quoted because they contain `$`.)
- **Redirect URIs:** `client1` registers `http://localhost:9000/callback`. `allowsRedirect` uses an exact string match only, because the authorization code is sent there, and looser matching lets attackers redirect it to themselves.

### 8. `GET /authorize`
The client sends the user's browser here to start the authorization code flow (§4.1.1). Checks run in two phases:

1. **Can it safely redirect back?** An unknown `client_id` or an unregistered `redirect_uri` gets a 400 error page and **never a redirect**, or the server would be an open redirector (§4.1.2.1).
2. **Everything else** goes back to the client as `redirect_uri?error=…&state=…`:
   - `response_type` other than `code` → `unsupported_response_type`
   - the client isn't allowed this flow → `unauthorized_client`
   - a scope it isn't allowed → `invalid_scope`
   - no PKCE `code_challenge`, or a method other than `S256` → `invalid_request`

A valid request shows a combined login and consent page. The request details travel to `POST /authorize` as hidden form fields, so that handler must check them all again. The page sets `X-Frame-Options: DENY` against clickjacking (§10.13), and `html/template` escapes every value taken from the URL.

Try it in a browser while the server runs:
```
http://localhost:8080/authorize?response_type=code&client_id=client1&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&scope=notes%3Aread&state=abc&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

### 9. `POST /authorize`
The login page posts here when the user presses Allow or Deny.

1. **Check the request again**, with the same two-phase rules as `GET`. The hidden form fields could have been edited, for example to widen the scope or point `redirect_uri` elsewhere.
2. **Deny** → redirect back with `error=access_denied`. No password needed.
3. **Wrong username or password** → show the page again with an error and the username filled in. No redirect, so the client learns nothing about failed logins.
4. **Allow with a correct login** → issue an authorization code and redirect to `redirect_uri?code=…&state=…`.

Each code is 256 random bits, stored under its hash, and valid for **1 minute**. It records the client, the user, the redirect URI, the scope and the PKCE challenge, so `/token` can check all of them, and a `used` flag so it can only be exchanged once.

Left out to keep the demo simple: a CSRF token on the login form, and a login session (users log in on every authorization).

### 10. Exchanging the code at `POST /token`
The client sends `grant_type=authorization_code`, `code`, `redirect_uri` and `code_verifier`, and authenticates with its own secret. After the usual client authentication and grant type checks:

1. **The code exists, hasn't expired and hasn't been used.** Checking it also marks it used, so even a failed attempt burns it: an attacker with a stolen code gets one guess at the PKCE verifier.
2. **It was issued to this client.**
3. **`redirect_uri` is identical** to the one sent to `/authorize` (§4.1.3).
4. **PKCE:** `BASE64URL(SHA256(code_verifier))` must equal the stored challenge (RFC 7636 §4.6).

Any failure is `invalid_grant`; a missing `code` is `invalid_request`. The token gets the scope the user approved, recorded with the code; a `scope` parameter is ignored for this grant.

Try the whole flow with curl (using alice's password and `SECRET1` from `.env`):
```sh
# 1. alice logs in and allows; the code is in the Location header
curl -i -d 'response_type=code&client_id=client1&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&scope=notes%3Aread&state=abc&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&username=alice&decision=allow' \
  --data-urlencode "password=$ALICE_PASSWORD" localhost:8080/authorize

# 2. client1 exchanges it within a minute, with the PKCE verifier
curl -u "client1:$SECRET1" -d grant_type=authorization_code -d code=<code> \
  --data-urlencode redirect_uri=http://localhost:9000/callback \
  -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk localhost:8080/token
```

Left out to keep the demo simple: revoking tokens already issued from a code when someone tries to reuse it (§4.1.2).

## Next steps
1. Tokens carry the user: a `userID` on tokens, returned as `sub` by `/introspect`, so the notes API can keep each user's notes separate
2. A `client-app` that runs the whole flow in a browser as `client1`
3. Refresh tokens with rotation
4. Revocation and metadata endpoints
5. JWT access tokens (optional), so resource servers can check tokens without calling `/introspect`
