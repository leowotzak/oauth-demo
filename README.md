# oauth-demo

[![CI](https://github.com/leowotzak/oauth-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/leowotzak/oauth-demo/actions/workflows/ci.yml)

An OAuth 2.0 authorization server written by hand in Go from the RFCs, plus a resource server and a client app that use it. Built to learn the protocol end to end: every OAuth rule here is implemented directly rather than delegated to an OAuth library.

It supports the [client credentials](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) and [authorization code](https://www.rfc-editor.org/rfc/rfc6749#section-4.1) grants with [PKCE](https://www.rfc-editor.org/rfc/rfc7636), [JWT access tokens](https://www.rfc-editor.org/rfc/rfc9068) that APIs check themselves, and [Bearer token](https://www.rfc-editor.org/rfc/rfc6750) protection with per-endpoint scopes and per-user data.

> **Tutorial only.** Plain HTTP, plaintext secrets and passwords in `.env` files, and Redis without a password. None of this is suitable for production.

## Architecture

```
 browser (alice)      client-app :9000        auth-server :8080       resource-server :8081
      │ 1. GET /login        │                        │                        │
      ├─────────────────────►│                        │                        │
      │ 2. 302 → /authorize?…&state&code_challenge    │                        │
      │◄─────────────────────┤                        │                        │
      │ 3. log in and approve on the auth server's page                        │
      ├──────────────────────────────────────────────►│                        │
      │ 4. 302 → /callback?code&state                 │                        │
      │◄──────────────────────────────────────────────┤                        │
      │ 5. GET /callback     │                        │                        │
      ├─────────────────────►│ 6. POST /token (code, verifier, secret)         │
      │                      ├───────────────────────►│                        │
      │                      │◄──── access token ─────┤                        │
      │                      │ 7. GET /notes (Bearer token)                    │
      │                      ├────────────────────────────────────────────────►│
      │                      │                        │◄── 8. GET jwks.json ───┤
      │                      │◄──────────────────────── 9. alice's notes ──────┤

 Client credentials (client2, client3) skips steps 1–5: the service calls
 POST /token with its own secret, then uses the token like step 7.
```

Steps 1–5 go through the browser (the front channel); 6–9 go directly between servers (the back channel). The code passes through the browser, which is why `state` and PKCE exist; the token never does.

The access token is a signed JWT. Step 8 happens only once: the notes API fetches the auth server's public key, then checks every token's signature itself, without calling the auth server again.

**[Illustrated version](https://claude.ai/artifact/BdPCWNvpmQ5naBjtfAVCBx):** this flow plus the checks `POST /token` runs for each grant.

| Module | Port | OAuth role |
|---|---|---|
| [`auth-server`](auth-server) | 8080 | Authorization server: users, clients, `/authorize`, `/token`, and its public key at `/.well-known/jwks.json` |
| [`resource-server`](resource-server) | 8081 | Resource server: a notes API protected by Bearer tokens |
| [`client-app`](client-app) | 9000 | Client: a web app that logs users in as `client1` |
| Redis | 6379 | Shared state: authorization codes, client-app sessions, revoked token IDs and notes |

The client app deliberately uses a standard OAuth client library, [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2). If it completes the flow against the hand-written server unchanged, the server follows the spec.

## Quick start

Requires Go 1.27 and Redis. Each module reads its own `.env`, so run each from its own folder:

```sh
docker compose up -d redis        # Redis on localhost:6379 (or any Redis you have)
cd auth-server && go run .        # terminal 1
cd resource-server && go run .    # terminal 2
cd client-app && go run .         # terminal 3
```

Open **http://localhost:9000**, click "Log in with auth-server", and log in as one of the demo users below. Watch the address bar move from the app to the auth server's login page and back. Each user sees only their own notes.

**Or with Docker:** `docker compose up --build`, then open the same URL. One [`Dockerfile`](Dockerfile) builds any of the three apps (`--build-arg SERVICE=…`) into a small non-root image, and [`compose.yaml`](compose.yaml) gives each its `.env` plus the addresses that change inside Docker. Containers reach each other by service name (`auth-server:8080`) on the back channel, while anything your browser follows stays on `localhost`. The apps wait for Redis to be healthy before starting, and its data lives in a volume, so notes survive `docker compose down`.

**Tests:**
```sh
go test ./...                     # in each module; uses fakes, no servers needed
./auth-server/test-curl.sh        # client credentials, against a running auth-server
./resource-server/test-curl.sh    # both flows end to end, with auth-server and resource-server running
```

[CI](.github/workflows/ci.yml) runs these on every push to `master` and every pull request: formatting, `go vet` and `go test -race` for each module, then the whole suite in Docker with both curl suites.

## Demo accounts

**Users** (log in on the auth server's page):

| Username | Password | ID (`sub`) | Starting notes |
|---|---|---|---|
| `alice` | `wonderland-42` | `user-1` | "Buy milk" |
| `bob` | `builder-42` | `user-2` | "Prepare for OAuth interview" |

**Clients** (secrets in `auth-server/.env`):

| Client | Grant | Allowed scopes | Default scope | Purpose |
|---|---|---|---|---|
| `client1` | `authorization_code` | `notes:read notes:write` | `notes:read` | The web app, played by `client-app` |
| `client2` | `client_credentials` | `notes:read` | `notes:read` | A read-only service |
| `client3` | `client_credentials` | `notes:read notes:write metrics:read` | `notes:read` | A service with several scopes |

## Design choices
- **JWT access tokens signed with Ed25519** ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)). The notes API checks them itself, so it doesn't depend on the auth server for every request. The trade-off: a token can't be revoked before it expires, so tokens last only 15 minutes.
- **Revocation through a deny list in Redis.** `POST /revoke` (RFC 7009) adds a token's ID (`jti`) to Redis until the token would have expired anyway, and the notes API checks that list after the signature. Logging out of the client app revokes its token. If Redis is down, the notes API **fails closed**, so a revoked token can never slip through.
- **Short-lived state lives in Redis**, with TTLs doing the expiry: authorization codes (redeemed with atomic `GETDEL`, so they're single use), client app sessions, and the deny list. Notes are there too. State survives restarts, and several copies of each app could share it.
- **Secrets, codes and session IDs are stored only as hashes**, in `.env` and in Redis. SHA-256 for long random values; bcrypt for human passwords, which are guessable.
- **Exact redirect URI matching**, and an auth server that never redirects to an unverified URI, even for errors.
- **PKCE is required, `S256` only.**
- **A failed code exchange burns the code**, so a stolen code gets one guess at the verifier.
- **The client app keeps tokens on its server** (backend for frontend); the browser only holds an `HttpOnly` session cookie.
- **Simplified on purpose.** The code skips production hardening such as validating config, rate limiting and CSRF tokens on the login form, so the protocol logic stays readable. Each module's README lists what it leaves out.

## Not implemented yet
- Refresh tokens with rotation
- Signing key rotation (there's one fixed key)
- Public clients (no secret, PKCE only)
- Authorization server metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414))
- OpenID Connect (identity, not just access)
