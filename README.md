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

```shell
$ ./auth
```

The schema in [schema.sql](./schema.sql) must be applied to the database before
the service starts.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Validate the OAuth2 client and redirect to Google |
| `GET` | `/callback` | Receive Google's code and issue an internal auth code |
| `POST` | `/token` | Exchange client credentials + code for a user token |
| `POST` | `/revoke` | Revoke a user token |

## Deployment

The provided [Dockerfile](./Dockerfile) builds a `gcr.io/distroless/static`
image. CI pushes to `registry.moonrhythm.io/deploys-app/auth:<git-sha>`.
