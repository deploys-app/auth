package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/acoshift/pgsql/pgctx"
)

const tokenPrefix = "deploys-api."

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
