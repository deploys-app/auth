package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/acoshift/pgsql/pgctx"
)

const tokenPrefix = "deploys-api."

// refreshTokenPrefix tags refresh tokens distinctly from access tokens so the
// two can never be confused. A refresh token lives in its own table and is only
// ever accepted at /token; presented as an API bearer it is rejected, since the
// apiserver and /introspect resolve only user_tokens.
const refreshTokenPrefix = "deploys-refresh."

// tokenTTLSeconds is the access-token lifetime. It is the single source of truth
// for both the expires_in reported to clients and the user_tokens row's
// expires_at (see insertToken), so the two can never drift.
const tokenTTLSeconds = 7 * 24 * 60 * 60

// refreshTokenTTLSeconds is the refresh-token lifetime. It is longer than the
// access token and rotated on every use (see handleRefreshTokenGrant), giving a
// sliding window: a client used at least once within this window keeps working
// without a full re-authorization.
const refreshTokenTTLSeconds = 30 * 24 * 60 * 60

func generateBase64RandomString(s int) string {
	b := make([]byte, s)
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b[:])
}

func generateToken() string {
	return tokenPrefix + generateBase64RandomString(32)
}

func generateRefreshToken() string {
	return refreshTokenPrefix + generateBase64RandomString(32)
}

func generateState() string {
	return generateBase64RandomString(24)
}

func generateCode() string {
	return generateBase64RandomString(32)
}

func generateSessionID() string {
	return generateBase64RandomString(32)
}

func generateClientID() string {
	return generateBase64RandomString(16)
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	// h.Write(secret)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// insertToken persists a hashed access token for email, expiring ttlSeconds from
// now. expires_at is computed from the same value reported to the client as
// expires_in, keeping the wire contract and the DB row in lockstep.
func insertToken(ctx context.Context, hashedToken, email string, ttlSeconds int) error {
	expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
	_, err := pgctx.Exec(ctx, `
		insert into user_tokens (token, email, expires_at)
		values ($1, $2, $3)
	`, hashedToken, email, expiresAt)
	return err
}

// insertRefreshToken persists a hashed refresh token bound to the issuing client,
// expiring ttlSeconds from now. Binding to client_id lets consumeRefreshToken
// reject a token replayed by a different client.
func insertRefreshToken(ctx context.Context, hashedToken, email, clientID string, ttlSeconds int) error {
	expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
	_, err := pgctx.Exec(ctx, `
		insert into refresh_tokens (token, email, client_id, expires_at)
		values ($1, $2, $3, $4)
	`, hashedToken, email, clientID, expiresAt)
	return err
}

// consumeRefreshToken atomically deletes a refresh token and returns its owner,
// enforcing single-use rotation: each refresh token is valid at most once. It
// returns sql.ErrNoRows when the token is unknown, expired, already rotated, or
// bound to a different client — all of which the caller treats as invalid_grant.
func consumeRefreshToken(ctx context.Context, hashedToken, clientID string) (email string, err error) {
	err = pgctx.QueryRow(ctx, `
		delete from refresh_tokens
		where token = $1 and client_id = $2 and expires_at > now()
		returning email
	`, hashedToken, clientID).Scan(&email)
	return
}

func deleteToken(ctx context.Context, token string) error {
	_, err := pgctx.Exec(ctx, `delete from user_tokens where token = $1`, token)
	return err
}

// revokeToken deletes a token by its hash from both the access-token and
// refresh-token stores, so a caller can revoke either kind by presenting its
// value (RFC 7009). The hashes never collide across the two tables, so one of the
// deletes is always a harmless no-op. Without this a refresh token — long-lived
// and rotating — could never be revoked, only waited out.
func revokeToken(ctx context.Context, hashedToken string) error {
	return pgctx.RunInTx(ctx, func(ctx context.Context) error {
		if _, err := pgctx.Exec(ctx, `delete from user_tokens where token = $1`, hashedToken); err != nil {
			return err
		}
		_, err := pgctx.Exec(ctx, `delete from refresh_tokens where token = $1`, hashedToken)
		return err
	})
}

// lookupToken resolves a hashed token to its owner email and expiry (unix
// seconds), returning sql.ErrNoRows when the token is unknown, expired, or
// scoped.
//
// Scoped tokens (a non-null scope_project_id, minted by me.generateToken) are
// deliberately excluded: introspection returns only the bare identity (sub),
// dropping the token's attenuation, so any resource server that trusts that sub
// would silently promote a narrowly-scoped agent token to its minter's full
// authority — a confused deputy. A scoped token is enforced ≤-minter only where
// its scope is re-evaluated (the apiserver Bearer path), so it must never
// resolve to a bare identity here. It therefore reads as inactive, exactly like
// an unknown token; the agent presents it directly to the apiserver instead.
func lookupToken(ctx context.Context, hashedToken string) (email string, exp int64, err error) {
	err = pgctx.QueryRow(ctx, `
		select email, extract(epoch from expires_at)::bigint
		from user_tokens
		where token = $1 and expires_at > now() and scope_project_id is null
	`, hashedToken).Scan(&email, &exp)
	return
}
