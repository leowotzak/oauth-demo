# resource-server

A small notes API that accepts access tokens issued by [`auth-server`](../auth-server). It's the **resource server** in OAuth terms: it holds the data, and it decides whether to serve a request based on the token it's given.

> **Tutorial only.** Plaintext HTTP, a plaintext secret in `.env`, and notes kept in memory.

## How a request is checked

```
client ──GET /notes──────────────────────► resource-server :8081
         Authorization: Bearer <token>          │
                                                │ POST /introspect  token=<token>
                                                │ (authenticates as notes-api)
                                                ▼
                                         auth-server :8080
                                                │
                                   {"active":true,"scope":"notes:read",…}
```

`requireScope` in `auth.go` runs before every handler (RFC 6750):

1. **Read the token** from `Authorization: Bearer <token>`. If it's missing: 401.
2. **Introspect it** by asking the auth server whether it's active and what scope it has (RFC 7662). If it's unknown or expired: 401 `invalid_token`. If the auth server can't be reached: 503.
3. **Check the scope** the endpoint needs. If it's missing: 403 `insufficient_scope`.

Errors go in the `WWW-Authenticate: Bearer` header, as RFC 6750 §3 requires.

| Endpoint | Needs scope |
|---|---|
| `GET /notes` | `notes:read` |
| `POST /notes` with body `{"text": "..."}` | `notes:write` |

**401 vs 403:** a 401 means the server doesn't know who you are, so get a valid token. A 403 means it knows who you are, but your token doesn't allow this action.

## Running it

```sh
cd auth-server && go run .        # terminal 1, :8080
cd resource-server && go run .    # terminal 2, :8081
./resource-server/test-curl.sh    # terminal 3: get real tokens and use them
go test ./...                     # unit tests use a fake auth server
```

By hand:
```sh
TOKEN=$(curl -s -u "client2:$SECRET2" -d grant_type=client_credentials localhost:8080/token | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" localhost:8081/notes
```

## Files

| File | Contents |
|---|---|
| `main.go` | The `server` struct, routes and startup |
| `auth.go` | Token checking: `introspect`, `requireScope` and Bearer errors |
| `notes.go` | The note handlers. They contain no OAuth code |
| `.env` | This service's own credentials for `/introspect`, and the introspection URL |

## Design choices
- **Introspection, not a shared store.** The notes API can't see the auth server's memory, so it asks over HTTP. This is how opaque tokens work. With JWTs, the API could check each token's signature itself without calling the auth server.
- **One introspection call per request.** It's simple, and a revoked or expired token is rejected immediately. A real service would usually cache the results briefly to cut down on calls.
- **The API is a registered client** (`notes-api`) with no grant types. It can call `/introspect` but can't get tokens of its own.
