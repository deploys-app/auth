package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/acoshift/pgsql/pgctx"
)

// newMock returns a mock *sql.DB plus its controller. The DB is closed via
// t.Cleanup. pgctx talks to it through the standard database/sql interface, so
// no transaction (begin/commit) expectations are needed for these handlers.
func newMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, mock
}

// withDB binds the mock DB to the request context the way pgctx.Middleware would.
func withDB(req *http.Request, db *sql.DB) *http.Request {
	return req.WithContext(pgctx.NewContext(req.Context(), db))
}

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

func assertExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// sqlNoRows is the error a QueryRow returns when nothing matched; the DB layer
// translates it into the ErrOAuth2*NotFound sentinels.
func sqlNoRows() error { return sql.ErrNoRows }
