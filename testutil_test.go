package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"testing"

	"github.com/acoshift/pgsql/pgctx"
	"github.com/lib/pq"
)

// pkcePair returns a PKCE verifier and its S256 challenge.
func pkcePair() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// fakeIDToken builds a JWT-shaped token whose payload carries the given email,
// matching what extractEmailFromIDToken expects (RawStdEncoding-encoded body).
func fakeIDToken(email string) string {
	payload := base64.RawStdEncoding.EncodeToString([]byte(`{"email":"` + email + `"}`))
	return "header." + payload + ".signature"
}

// --- seeding helpers (operate on a context already carrying the DB) ---

func seedConfidentialClient(t *testing.T, ctx context.Context, id, secret, redirectGlob string) {
	t.Helper()
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_clients (id, secret, redirect_uri, token_endpoint_auth_method)
		values ($1, $2, $3, 'client_secret_post')
	`, id, secret, redirectGlob)
	if err != nil {
		t.Fatalf("seed confidential client: %v", err)
	}
}

func seedPublicClient(t *testing.T, ctx context.Context, id string, redirectURIs ...string) {
	t.Helper()
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_clients (id, redirect_uris, token_endpoint_auth_method)
		values ($1, $2, 'none')
	`, id, pq.Array(redirectURIs))
	if err != nil {
		t.Fatalf("seed public client: %v", err)
	}
}

func seedCode(t *testing.T, ctx context.Context, id, clientID, email, challenge, method, redirect, resource string) {
	t.Helper()
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_codes (id, client_id, email, code_challenge, code_challenge_method, redirect_uri, resource)
		values ($1, $2, $3, $4, $5, $6, $7)
	`, id, clientID, email, challenge, method, redirect, resource)
	if err != nil {
		t.Fatalf("seed code: %v", err)
	}
}

func seedSession(t *testing.T, ctx context.Context, id, clientID, state, cbState, cbURL, challenge, method, resource string) {
	t.Helper()
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_sessions (id, client_id, state, callback_state, callback_url, code_challenge, code_challenge_method, resource)
		values ($1, $2, $3, $4, $5, $6, $7, $8)
	`, id, clientID, state, cbState, cbURL, challenge, method, resource)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

// pgctxExec runs an arbitrary statement against the test DB (for one-off seeds
// that the typed helpers don't cover, e.g. an already-expired token).
func pgctxExec(t *testing.T, ctx context.Context, query string, args ...any) (sql.Result, error) {
	t.Helper()
	return pgctx.Exec(ctx, query, args...)
}

func seedToken(t *testing.T, ctx context.Context, hashedToken, email string) {
	t.Helper()
	_, err := pgctx.Exec(ctx, `
		insert into user_tokens (token, email, expires_at)
		values ($1, $2, now() + interval '7 days')
	`, hashedToken, email)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
}

// --- assertion helpers ---

func tokenEmail(t *testing.T, ctx context.Context, hashedToken string) (string, bool) {
	t.Helper()
	var email string
	err := pgctx.QueryRow(ctx, `select email from user_tokens where token = $1`, hashedToken).Scan(&email)
	if err != nil {
		return "", false
	}
	return email, true
}

func countRows(t *testing.T, ctx context.Context, table string) int {
	t.Helper()
	var n int
	if err := pgctx.QueryRow(ctx, `select count(*) from `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func clientRedirectURIs(t *testing.T, ctx context.Context, id string) ([]string, bool) {
	t.Helper()
	var uris []string
	err := pgctx.QueryRow(ctx, `select redirect_uris from oauth2_clients where id = $1`, id).Scan(&uris)
	if err != nil {
		return nil, false
	}
	return uris, true
}

// codeEmailPKCE reads back a minted oauth2_codes row (without consuming it).
func codeEmailPKCE(t *testing.T, ctx context.Context, id string) (email, challenge, method string) {
	t.Helper()
	err := pgctx.QueryRow(ctx, `
		select email, code_challenge, code_challenge_method
		from oauth2_codes
		where id = $1
	`, id).Scan(&email, &challenge, &method)
	if err != nil {
		t.Fatalf("read code %q: %v", id, err)
	}
	return email, challenge, method
}

// oneSessionPKCE returns the PKCE challenge/method and callback URL of the only
// session row (the redirect handler is expected to have created exactly one).
func oneSessionPKCE(t *testing.T, ctx context.Context) (challenge, method, callbackURL string) {
	t.Helper()
	err := pgctx.QueryRow(ctx, `
		select code_challenge, code_challenge_method, callback_url
		from oauth2_sessions
		limit 1
	`).Scan(&challenge, &method, &callbackURL)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	return challenge, method, callbackURL
}
