# client-app

A small web app that plays **`client1`** in the authorization code flow with PKCE. A user logs in through [`auth-server`](../auth-server), and the app then reads and adds their notes through [`resource-server`](../resource-server).

Unlike the two servers, this module **uses a library**: [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2), a standard OAuth client. That makes it a check on the hand-written auth server: if a widely used client library completes the flow unchanged, the server follows the spec.

> **Tutorial only.** Plain HTTP, a plaintext client secret in `.env`, and sessions kept in memory.

## Running it

```sh
cd auth-server && go run .        # :8080
cd resource-server && go run .    # :8081
cd client-app && go run .         # :9000
```

Open http://localhost:9000 and log in as `alice` / `wonderland-42` or `bob` / `builder-42`. Each sees only their own notes.

`go test ./...` runs the app against a fake auth server and notes API.

## The flow

```
browser ──GET /login──────► client-app       saves state + PKCE verifier in the session
        ◄──302 /authorize?…&state&code_challenge──
        ──────────────────► auth-server      login and consent page
        ◄──302 /callback?code&state──────────
        ──GET /callback───► client-app       checks state, then:
                              ──POST /token (code, redirect_uri, code_verifier; Basic auth)──► auth-server
                              ◄── access token ──
                            keeps the token in the session
        ◄──302 / ──
        ──GET /───────────► client-app ──GET /notes (Bearer token)──► resource-server
```

| Route | What it does |
|---|---|
| `GET /` | A login button, or the user's notes and a form to add one |
| `GET /login` | Saves a fresh `state` and PKCE verifier, then redirects to `/authorize` |
| `GET /callback` | Checks `state`, handles `?error=`, exchanges the code, stores the token |
| `POST /notes` | Adds a note through the notes API |
| `POST /logout` | Forgets the token |

How the library calls map onto the protocol:

| Call | What it does |
|---|---|
| `oauth2.GenerateVerifier()` | A random 43-character PKCE verifier |
| `AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))` | Builds the `/authorize` URL with `code_challenge` and `code_challenge_method=S256` |
| `Exchange(ctx, code, oauth2.VerifierOption(verifier))` | `POST /token` with the code, `redirect_uri` and `code_verifier`, authenticated with HTTP Basic |
| `Client(ctx, token)` | An HTTP client that adds `Authorization: Bearer <token>` to every request |

## Security choices
- **`state` is checked before anything else**, including error responses, and is single use. A callback the browser didn't start is rejected (CSRF).
- **The PKCE verifier never leaves the server.** Only its hash, the challenge, goes through the browser.
- **The access token stays on the server** ("backend for frontend"). The browser only holds a random session ID in an `HttpOnly`, `SameSite=Lax` cookie, so page scripts can't read it, and other sites can't make the browser send it with a POST.
- **The client secret is only used on the back channel**, for the `/token` request.

## What it doesn't do
- **Know the user's name.** OAuth grants access, not identity: the app only learns the user's ID (`user-1`) from the notes API. Logging users in properly is what OpenID Connect adds, with an ID token.
- **Revoke the token on logout.** It forgets the token, but the token stays valid at the auth server until it expires, since there's no `/revoke` endpoint yet.
- **Refresh tokens.** When the token expires, the user logs in again.
