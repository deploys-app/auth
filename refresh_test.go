package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// decodeTokenResponse reads the standard /token JSON body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func decodeTokenResponse(t *testing.T, rec *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	var resp tokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp
}

// --- authorization_code path now issues real refresh tokens for public clients ---

func TestTokenHandler_Public_IssuesRealRefreshToken(t *testing.T) {
	t.Parallel()
	verifier, challenge := pkcePair()
	const redirect = "http://127.0.0.1:5000/callback"

	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", redirect)
	seedCode(t, ctx, "abc", "cli", "user@example.com", challenge, "S256", redirect, "")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"code":          {"abc"},
		"code_verifier": {verifier},
		"redirect_uri":  {redirect},
	}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeTokenResponse(t, rec)

	// The refresh token is a distinct, refresh-prefixed credential — not the
	// access token echoed back.
	if !strings.HasPrefix(resp.RefreshToken, refreshTokenPrefix) {
		t.Errorf("refresh_token %q missing prefix %q", resp.RefreshToken, refreshTokenPrefix)
	}
	if resp.RefreshToken == resp.AccessToken {
		t.Error("refresh_token must differ from access_token for public clients")
	}
	// It is persisted (hashed) against the right email and client.
	if email, ok := refreshTokenEmail(t, ctx, hashToken(resp.RefreshToken)); !ok || email != "user@example.com" {
		t.Errorf("persisted refresh token email = %q (ok=%v), want user@example.com", email, ok)
	}
}

func TestTokenHandler_Confidential_NoRefreshTokenRow(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")
	seedCode(t, ctx, "abc", "web", "user@example.com", "", "", "https://app.example.com/cb", "")

	form := url.Values{"client_id": {"web"}, "client_secret": {"topsecret"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeTokenResponse(t, rec)
	// Legacy contract preserved: confidential clients get the access token echoed
	// as refresh_token, and no refresh_tokens row is minted.
	if resp.RefreshToken != resp.AccessToken {
		t.Errorf("access_token (%q) should equal refresh_token (%q) for confidential clients", resp.AccessToken, resp.RefreshToken)
	}
	if n := countRows(t, ctx, "refresh_tokens"); n != 0 {
		t.Errorf("refresh_tokens = %d, want 0 (confidential clients get no real refresh token)", n)
	}
}

// --- refresh_token grant ---

func TestRefreshTokenGrant_Success(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:5000/callback")
	oldRefresh := generateRefreshToken()
	seedRefreshToken(t, ctx, hashToken(oldRefresh), "user@example.com", "cli")

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"cli"},
		"refresh_token": {oldRefresh},
	}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeTokenResponse(t, rec)

	if !strings.HasPrefix(resp.AccessToken, tokenPrefix) {
		t.Errorf("access_token %q missing prefix %q", resp.AccessToken, tokenPrefix)
	}
	if !strings.HasPrefix(resp.RefreshToken, refreshTokenPrefix) {
		t.Errorf("refresh_token %q missing prefix %q", resp.RefreshToken, refreshTokenPrefix)
	}
	if resp.RefreshToken == oldRefresh {
		t.Error("refresh token must rotate (new value), got the same value back")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.ExpiresIn != tokenTTLSeconds {
		t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, tokenTTLSeconds)
	}
	// A fresh access token is persisted for the user.
	if email, ok := tokenEmail(t, ctx, hashToken(resp.AccessToken)); !ok || email != "user@example.com" {
		t.Errorf("persisted access token email = %q (ok=%v), want user@example.com", email, ok)
	}
	// The old refresh token is consumed; the new one is persisted.
	if _, ok := refreshTokenEmail(t, ctx, hashToken(oldRefresh)); ok {
		t.Error("old refresh token must be consumed (single-use)")
	}
	if email, ok := refreshTokenEmail(t, ctx, hashToken(resp.RefreshToken)); !ok || email != "user@example.com" {
		t.Errorf("rotated refresh token email = %q (ok=%v), want user@example.com", email, ok)
	}
	if n := countRows(t, ctx, "refresh_tokens"); n != 1 {
		t.Errorf("refresh_tokens = %d, want 1 (old consumed, new minted)", n)
	}
}

func TestRefreshTokenGrant_RotatedTokenRejected(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:5000/callback")
	oldRefresh := generateRefreshToken()
	seedRefreshToken(t, ctx, hashToken(oldRefresh), "user@example.com", "cli")

	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"cli"}, "refresh_token": {oldRefresh}}

	// First use succeeds.
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("first refresh status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Replaying the now-rotated token fails.
	rec = httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed refresh status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")
}

func TestRefreshTokenGrant_Expired(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:5000/callback")
	expired := generateRefreshToken()
	if _, err := pgctxExec(t, ctx, `
		insert into refresh_tokens (token, email, client_id, expires_at)
		values ($1, $2, $3, now() - interval '1 hour')
	`, hashToken(expired), "user@example.com", "cli"); err != nil {
		t.Fatalf("seed expired refresh token: %v", err)
	}

	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"cli"}, "refresh_token": {expired}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")
	if n := countRows(t, ctx, "user_tokens"); n != 0 {
		t.Errorf("user_tokens = %d, want 0 (no access token on expired refresh)", n)
	}
}

func TestRefreshTokenGrant_WrongClient(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "owner", "http://127.0.0.1:5000/callback")
	seedPublicClient(t, ctx, "attacker", "http://127.0.0.1:6000/callback")
	refresh := generateRefreshToken()
	seedRefreshToken(t, ctx, hashToken(refresh), "user@example.com", "owner")

	// Present the owner's refresh token under a different client_id.
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"attacker"}, "refresh_token": {refresh}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")
	// The owner's token must NOT be consumed by another client's attempt.
	if _, ok := refreshTokenEmail(t, ctx, hashToken(refresh)); !ok {
		t.Error("owner's refresh token must survive a foreign-client attempt")
	}
}

func TestRefreshTokenGrant_MissingRefreshToken(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:5000/callback")

	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"cli"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")
}

func TestRefreshTokenGrant_MissingClientID(t *testing.T) {
	t.Parallel()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"deploys-refresh.x"}}
	rec := httptest.NewRecorder()
	// Rejected before any DB access.
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")
}

func TestRefreshTokenGrant_UnknownClient(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx() // empty DB: client lookup misses

	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"ghost"}, "refresh_token": {"deploys-refresh.x"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_client")
}

func TestRevoke_RefreshToken(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:5000/callback")
	refresh := generateRefreshToken()
	seedRefreshToken(t, ctx, hashToken(refresh), "user@example.com", "cli")

	// Revoke by presenting the refresh token value.
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(`{"token":"`+refresh+`"}`))
	rec := httptest.NewRecorder()
	RevokePostHandler{}.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// The refresh token is deleted and can no longer be exchanged.
	if _, ok := refreshTokenEmail(t, ctx, hashToken(refresh)); ok {
		t.Error("refresh token must be deleted after revoke")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"cli"}, "refresh_token": {refresh}}
	rec = httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("exchange of revoked refresh status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")
}

func TestRefreshTokenGrant_Confidential_RequiresSecret(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")
	refresh := generateRefreshToken()
	seedRefreshToken(t, ctx, hashToken(refresh), "user@example.com", "web")

	// Missing secret → invalid_request.
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"web"}, "refresh_token": {refresh}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing secret: status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")

	// Wrong secret → invalid_client.
	form.Set("client_secret", "wrong")
	rec = httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: status = %d, want 401", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_client")

	// The refresh token must survive both rejected attempts.
	if _, ok := refreshTokenEmail(t, ctx, hashToken(refresh)); !ok {
		t.Error("refresh token must not be consumed on failed client authentication")
	}

	// Correct secret → success.
	form.Set("client_secret", "topsecret")
	rec = httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("correct secret: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}
