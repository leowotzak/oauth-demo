# client-app

A small web app that plays **`client1`**: it logs users in through [`auth-server`](../auth-server) with the authorization code flow and PKCE, then reads and adds their notes through [`resource-server`](../resource-server). See the [project README](../README.md) for how to run all three and log in.

Unlike the servers, it **uses a library**, [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2), which doubles as a check that the hand-written auth server follows the spec.

```sh
go run .          # http://localhost:9000 (needs auth-server and resource-server running)
go test ./...     # uses a fake auth server and notes API
```

| Route | What it does |
|---|---|
| `GET /` | A login button, or the user's notes and a form to add one |
| `GET /login` | Saves a fresh `state` and PKCE verifier in the session, then redirects to `/authorize` |
| `GET /callback` | Checks `state`, handles `?error=`, exchanges the code, stores the token |
| `POST /notes` | Adds a note through the notes API |
| `POST /logout` | Forgets the token |

## How the library calls map onto the protocol

| Call | What it does |
|---|---|
| `oauth2.GenerateVerifier()` | A random 43-character PKCE verifier |
| `AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))` | Builds the `/authorize` URL with `code_challenge` and `code_challenge_method=S256` |
| `Exchange(ctx, code, oauth2.VerifierOption(verifier))` | `POST /token` with the code, `redirect_uri` and `code_verifier`, using HTTP Basic |
| `Client(ctx, token)` | An HTTP client that adds `Authorization: Bearer <token>` to every request |

## Security choices
- **`state` is checked first**, even before error responses, and is single use. A callback the browser didn't start is rejected (CSRF).
- **The PKCE verifier and client secret never leave the server.** Only the challenge goes through the browser.
- **The access token stays on the server** (backend for frontend). The browser holds only a random session ID in an `HttpOnly`, `SameSite=Lax` cookie.

## Limitations
- **It doesn't know the user's name**, only their ID (`user-1`) from the notes API. OAuth grants access, not identity; that's what OpenID Connect adds.
- **Logging out doesn't end the token** at the auth server, which has no revocation endpoint yet.
- **There are no refresh tokens**, so users log in again when the token expires after an hour.
- **Sessions are kept in memory.**
