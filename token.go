package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/acoshift/pgsql/pgctx"
)

const tokenPrefix = "deploys-api."

// tokenTTLSeconds mirrors the 7-day TTL applied to user_tokens rows; reported
// to clients as expires_in.
const tokenTTLSeconds = 7 * 24 * 60 * 60

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

func insertToken(ctx context.Context, hashedToken string, email string) error {
	_, err := pgctx.Exec(ctx, `
		insert into user_tokens (token, email, expires_at)
		values ($1, $2, now() + interval '7 days')
	`, hashedToken, email)
	return err
}

func deleteToken(ctx context.Context, token string) error {
	_, err := pgctx.Exec(ctx, `delete from user_tokens where token = $1`, token)
	return err
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
