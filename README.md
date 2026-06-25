# Deploys.app - Auth

Minimal OAuth2 authentication service for Deploys.app. Acts as an OAuth2
authorization server backed by Google as the identity provider.

## Build

```shell
$ go build -o auth .
```

## Run

Required environment variables:

| Variable | Description |
|---|---|
| `SQL_URL` | PostgreSQL connection string |
| `OAUTH2_CLIENT_ID` | Google OAuth app client ID |
| `OAUTH2_CLIENT_SECRET` | Google OAuth app client secret |
| `PORT` | Listen port (default: `8080`) |
| `BASE_URL` | Public base URL of this service (default: `https://auth.deploys.app`) |
| `INTROSPECTION_TOKEN` | Shared secret for the `/introspect` endpoint; if unset, introspection is disabled |

```shell
$ ./auth
```

The schema in [schema.sql](./schema.sql) must be applied to the database before
the service starts.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/.well-known/oauth-authorization-server` | OAuth 2.0 Authorization Server Metadata (RFC 8414) |
| `GET` | `/` | Validate the OAuth2 client and redirect to Google (authorize endpoint; supports PKCE) |
| `GET` | `/callback` | Receive Google's code and issue an internal auth code |
| `POST` | `/token` | Exchange code (+ secret or PKCE verifier) for a user token, or a refresh token for a fresh one |
| `POST` | `/register` | Dynamic Client Registration for public clients (RFC 7591) |
| `POST` | `/introspect` | Token introspection for resource servers (RFC 7662) |
| `POST` | `/revoke` | Revoke an access token or a refresh token by its value |

### MCP / public clients

The service is an OAuth 2.1 authorization server. CLI / MCP clients register
dynamically at `/register` (public clients, no secret), use **PKCE (S256)** at
the authorize and token endpoints, and may use loopback redirect URIs
(`http://127.0.0.1:<port>`). Confidential web clients keep using
`client_secret` as before. A resource server validates issued bearer tokens via
`/introspect` (authenticated with `INTROSPECTION_TOKEN`).

### Refresh tokens

The access token issued at `/token` is short-lived (7 days). Public clients
(CLI / MCP connector) also receive a **refresh token** and can exchange it for a
fresh access token with `grant_type=refresh_token` (`client_id` +
`refresh_token`), so a connector no longer breaks mid-session on expiry — it
silently refreshes instead of forcing a full browser re-authorization.

Refresh tokens are **single-use and rotating**: every refresh returns a new
refresh token and invalidates the one presented (a replayed token is rejected
with `invalid_grant`). They live in their own `refresh_tokens` table (never
`user_tokens`), are bound to the issuing client, and have a longer, sliding TTL
(30 days, reset on each use). Confidential web clients keep their cookie session
and do not use this grant — they receive no refresh token.

`/register` mints a permanent public-client row, so it is **rate-limited per
source IP** and dynamically-registered clients are **garbage-collected when idle**
(reaped after 90 days with no authorize; `last_used_at` is stamped on every
authorize, so a reused client never expires). Operator-seeded and confidential
clients are never reaped. The deploys CLI ships a baked-in `deploys-cli` public
client (seeded by `schema/05_seed_cli_client.sql`) so ordinary CLI logins skip
`/register` entirely.

## Deployment

The provided [Dockerfile](./Dockerfile) builds a `gcr.io/distroless/static`
image. CI pushes to `registry.moonrhythm.io/deploys-app/auth:<git-sha>`.
