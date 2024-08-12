package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acoshift/pgsql/pgctx"
)

var (
	ErrOAuth2ClientNotFound  = errors.New("oauth2: client not found")
	ErrOAuth2CodeNotFound    = errors.New("oauth2: code not found")
	ErrOAuth2SessionNotFound = errors.New("oauth2: session not found")
)

type OAuth2Client struct {
	ID          string
	Secret      string
	RedirectURI string
}

type Session struct {
	ClientID      string
	State         string
	CallbackState string
	CallbackURL   string
}

func getOAuth2Client(ctx context.Context, clientID string) (*OAuth2Client, error) {
	var x OAuth2Client
	err := pgctx.QueryRow(ctx, `
		select id, secret, redirect_uri
		from oauth2_clients
		where id = $1
	`, clientID).Scan(
		&x.ID, &x.Secret, &x.RedirectURI,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuth2ClientNotFound
	}
	if err != nil {
		return nil, err
	}
	return &x, nil
}

func insertOAuth2Code(ctx context.Context, clientID, code, email string) error {
	_, err := pgctx.Exec(ctx, `
		insert into oauth2_codes (id, client_id, email)
		values ($1, $2, $3)
	`, code, clientID, email)
	return err
}

func getOAuth2EmailFromCode(ctx context.Context, clientID, code string) (string, error) {
	var email string
	err := pgctx.QueryRow(ctx, `
		delete from oauth2_codes
		where id = $1 and client_id = $2 and now() < created_at + interval '1 hour'
		returning email
	`, code, clientID).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrOAuth2CodeNotFound
	}
	if err != nil {
		return "", err
	}
	return email, nil
}

func getSession(ctx context.Context, sessionID string) (*Session, error) {
	var x Session
	err := pgctx.QueryRow(ctx, `
		select client_id, state, callback_state, callback_url
		from oauth2_sessions
		where id = $1 and now() < created_at + interval '1 hour'
	`, sessionID).Scan(
		&x.ClientID, &x.State, &x.CallbackState, &x.CallbackURL,
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
		insert into oauth2_sessions (id, client_id, state, callback_state, callback_url)
		values ($1, $2, $3, $4, $5)
	`, sessionID, session.ClientID, session.State, session.CallbackState, session.CallbackURL)
	return err
}
