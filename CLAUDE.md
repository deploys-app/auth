# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
go build -o auth .             # build binary
go vet ./...                   # lint
go test ./...                  # run tests
```

Handler tests run against a real CockroachDB: `tu.Setup()` starts an isolated
in-memory `cockroach-go/v2/testserver` per test and `schema.Migrate` applies the
embedded `schema/*.sql` migrations. `newTestDB(t)` (setup_test.go) returns a
`*tu.Context`; use `db.Ctx()` for both seeding (via `pgctx`) and the request
context. Google's token endpoint is stubbed through the `googleTokenURL` package
var. Tests download the CockroachDB binary on first run.

### Required environment variables

| Variable | Description |
|---|---|
| `SQL_URL` | PostgreSQL connection string |
| `OAUTH2_CLIENT_ID` | Google OAuth app client ID |
| `OAUTH2_CLIENT_SECRET` | Google OAuth app client secret |
| `PORT` | Listen port (default: `8080`) |
| `BASE_URL` | Public base URL of this service (default: `https://auth.deploys.app`) |
| `INTROSPECTION_TOKEN` | Shared secret guarding `POST /introspect`; unset disables the endpoint |

## Architecture

This is a minimal OAuth2 authentication service for Deploys.app. It acts as an OAuth2 authorization server backed by Google as the identity provider.

### Entry point

`main.go` reads env vars, opens a PostgreSQL connection, registers handlers on a `http.ServeMux`, wraps it with `pgctx.Middleware` (binds the DB to each request context), and calls `http.ListenAndServe`. All Go files live in the project root under `package main`.

### HTTP endpoints

| Method | Path | Handler | Purpose |
|---|---|---|---|
| `GET` | `/` | `RedirectHandler` | Validates the OAuth2 client and redirects the user to Google |
| `GET` | `/callback` | `CallbackHandler` | Receives Google's code, exchanges it for an ID token, issues an internal auth code |
| `POST` | `/token` | `TokenHandler` | Exchanges client credentials + internal code for a long-lived user token |
| `POST` | `/revoke` | `RevokePostHandler` | Deletes a user token by its hash |

### Database access pattern

`github.com/acoshift/pgsql` / `pgctx` is the only DB layer. Calling `pgctx.Middleware(db)` stores the `*sql.DB` in the request context; handlers then call `pgctx.Exec(ctx, ...)` or `pgctx.QueryRow(ctx, ...)` directly — there is no ORM or repository struct.

All DB logic lives in `oauth2.go` (session/code helpers) and `token.go` (token hashing and persistence).

### Session & token lifecycle

- **OAuth2 sessions** (`oauth2_sessions`) — created by `RedirectHandler`, deleted on first read by `CallbackHandler`. 1-hour TTL enforced in the WHERE clause.
- **OAuth2 codes** (`oauth2_codes`) — created by `CallbackHandler`, consumed atomically (DELETE … RETURNING) by `TokenHandler`. 1-hour TTL.
- **User tokens** (`user_tokens`) — 7-day TTL, stored as SHA-256 hashes. Revoked by `RevokePostHandler`.

### Key decisions

- No framework — plain `net/http` + `http.ServeMux`.
- No test files; no graceful shutdown / signal handling.
- Google is the only upstream identity provider (hardcoded endpoints in `handler.go`).
- Docker image uses `gcr.io/distroless/static` for a minimal runtime.
- CI builds and pushes to `registry.moonrhythm.io/deploys-app/auth:<git-sha>`.
