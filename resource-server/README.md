# resource-server

A notes API protected by access tokens from [`auth-server`](../auth-server): the **resource server** in OAuth terms. It never sees passwords or client secrets, only the Bearer tokens clients send it. See the [project README](../README.md) for how it fits with the other modules.

```sh
go run .          # http://localhost:8081 (needs auth-server running)
go test ./...     # uses a fake auth server
./test-curl.sh    # both flows end to end, with auth-server and resource-server running
```

| Endpoint | Needs scope |
|---|---|
| `GET /notes` → `{"owner": "user-1", "notes": [...]}` | `notes:read` |
| `POST /notes` with body `{"text": "..."}` | `notes:write` |

## How a request is checked

`requireScope` in `auth.go` runs before every handler ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)):

1. **Read the token** from `Authorization: Bearer <token>`. Missing → 401.
2. **Introspect it:** ask the auth server whether it's active and what it allows, authenticating as the `notes-api` client (credentials in `.env`). Unknown or expired → 401 `invalid_token`. Auth server unreachable → 503 (fail closed).
3. **Check the scope** the endpoint needs. Missing → 403 `insufficient_scope`.
4. **Work out the owner** and pass it to the handler: the token's `sub` (its user), or `client:<id>` for client credentials tokens, which have no user.

Error codes go in the `WWW-Authenticate: Bearer` header (§3). A 401 means "get a valid token"; a 403 means "your valid token doesn't allow this". The note handlers in `notes.go` contain no OAuth code, and notes are stored per owner, so alice and bob see only their own.

## Design choices
- **One introspection call per request.** Expired or deleted tokens are rejected immediately; a real service would usually cache results briefly.
- **Tokens without a user get their own notes**, owned by the client. The stricter alternative is to reject them on endpoints about "my" data.
- **No audience check.** It accepts any active token from the auth server, including tokens meant for other APIs.
- **The `Bearer` prefix is matched case-sensitively**, although HTTP says scheme names are case-insensitive.
