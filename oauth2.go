package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/acoshift/pgsql/pgctx"
	"github.com/lib/pq"
)

var (
	ErrOAuth2ClientNotFound  = errors.New("oauth2: client not found")
	ErrOAuth2CodeNotFound    = errors.New("oauth2: code not found")
	ErrOAuth2SessionNotFound = errors.New("oauth2: session not found")
)

type OAuth2Client struct {
	ID                      string
	Secret                  string
	RedirectURIs            []string // exact URIs, or "regexp:" patterns (operator-provisioned only)
	TokenEndpointAuthMethod string   // "client_secret_post" or "none"
	ClientName              string
}

// IsPublic reports whether the client authenticates without a secret (PKCE only).
func (c *OAuth2Client) IsPublic() bool {
	return c.TokenEndpointAuthMethod == "none"
}

type Session struct {
	ClientID            string
	State               string
	CallbackState       string
	CallbackURL         string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

type OAuth2Code struct {
	Email               string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	Resource            string
}

func getOAuth2Client(ctx context.Context, clientID string) (*OAuth2Client, error) {
	var x OAuth2Client
	var secret sql.NullString
	err := pgctx.QueryRow(ctx, `
		select id, secret, redirect_uris, token_endpoint_auth_method
		from oauth2_clients
		where id = $1
	`, clientID).Scan(
		&x.ID, &secret, &x.RedirectURIs, &x.TokenEndpointAuthMethod,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuth2ClientNotFound
	}
	if err != nil {
		return nil, err
	}
	x.Secret = secret.String
	return &x, nil
}

// insertOAuth2Client persists a dynamically registered public client. It is
// marked dynamically_registered so the cleanup worker may reap it when idle;
// operator-seeded and confidential clients are inserted elsewhere and keep the
// column's default of false (never reaped).
func insertOAuth2Client(ctx context.Context, c *OAuth2Client) error {
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_clients (id, secret, redirect_uris, token_endpoint_auth_method, client_name, dynamically_registered)
		values ($1, null, $2, $3, $4, true)
	`, c.ID, pq.Array(c.RedirectURIs), c.TokenEndpointAuthMethod, c.ClientName)
	return err
}

// touchClientLastUsed records that a client was just used (at authorize time),
// so idle GC reaps by last use rather than creation age. Best-effort: a failure
// must not break the login, so the error is logged and swallowed.
func touchClientLastUsed(ctx context.Context, clientID string) {
	_, err := pgctx.Exec(ctx, `update oauth2_clients set last_used_at = now() where id = $1`, clientID)
	if err != nil {
		slog.WarnContext(ctx, "touch client last_used_at", "error", err, "client_id", clientID)
	}
}

func insertOAuth2Code(ctx context.Context, clientID, code string, c *OAuth2Code) error {
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_codes (id, client_id, email, code_challenge, code_challenge_method, redirect_uri, resource)
		values ($1, $2, $3, $4, $5, $6, $7)
	`, code, clientID, c.Email, c.CodeChallenge, c.CodeChallengeMethod, c.RedirectURI, c.Resource)
	return err
}

// getOAuth2Code atomically consumes a code, returning the associated email and
// the PKCE / redirect binding stored when it was issued. 1-hour TTL.
func getOAuth2Code(ctx context.Context, clientID, code string) (*OAuth2Code, error) {
	var x OAuth2Code
	err := pgctx.QueryRow(ctx, `
		delete from oauth2_codes
		where id = $1 and client_id = $2 and now() < created_at + interval '1 hour'
		returning email, code_challenge, code_challenge_method, redirect_uri, resource
	`, code, clientID).Scan(
		&x.Email, &x.CodeChallenge, &x.CodeChallengeMethod, &x.RedirectURI, &x.Resource,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuth2CodeNotFound
	}
	if err != nil {
		return nil, err
	}
	return &x, nil
}

func getSession(ctx context.Context, sessionID string) (*Session, error) {
	var x Session
	err := pgctx.QueryRow(ctx, `
		select client_id, state, callback_state, callback_url, code_challenge, code_challenge_method, resource
		from oauth2_sessions
		where id = $1 and now() < created_at + interval '1 hour'
	`, sessionID).Scan(
		&x.ClientID, &x.State, &x.CallbackState, &x.CallbackURL, &x.CodeChallenge, &x.CodeChallengeMethod, &x.Resource,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuth2SessionNotFound
	}
	if err != nil {
		return nil, err
	}

	_, err = pgctx.Exec(ctx, "delete from oauth2_sessions where id = $1", sessionID)
	if err != nil {
		return nil, err
	}

	return &x, nil
}

func saveSession(ctx context.Context, sessionID string, session *Session) error {
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_sessions (id, client_id, state, callback_state, callback_url, code_challenge, code_challenge_method, resource)
		values ($1, $2, $3, $4, $5, $6, $7, $8)
	`, sessionID, session.ClientID, session.State, session.CallbackState, session.CallbackURL,
		session.CodeChallenge, session.CodeChallengeMethod, session.Resource)
	return err
}
