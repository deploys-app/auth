package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func postForm(t *testing.T, path string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// --- OLD FLOW (regression): confidential client + client_secret ---

func TestTokenHandler_Confidential_Success(t *testing.T) {
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
	var resp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Backward compatibility: the legacy client reads refresh_token.
	if !strings.HasPrefix(resp.RefreshToken, tokenPrefix) {
		t.Errorf("refresh_token %q missing prefix %q", resp.RefreshToken, tokenPrefix)
	}
	if resp.AccessToken != resp.RefreshToken {
		t.Errorf("access_token (%q) should equal refresh_token (%q)", resp.AccessToken, resp.RefreshToken)
	}
	if resp.ExpiresIn != tokenTTLSeconds {
		t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, tokenTTLSeconds)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	// The token is persisted (hashed) against the right email.
	if email, ok := tokenEmail(t, ctx, hashToken(resp.RefreshToken)); !ok || email != "user@example.com" {
		t.Errorf("persisted token email = %q (ok=%v), want user@example.com", email, ok)
	}
	// The code is single-use.
	if n := countRows(t, ctx, "oauth2_codes"); n != 0 {
		t.Errorf("oauth2_codes = %d, want 0 (code consumed)", n)
	}
}

func TestTokenHandler_Confidential_WrongSecret(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")
	seedCode(t, ctx, "abc", "web", "user@example.com", "", "", "https://app.example.com/cb", "")

	form := url.Values{"client_id": {"web"}, "client_secret": {"wrong"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_client")
	// The code must not be consumed on a failed exchange.
	if n := countRows(t, ctx, "oauth2_codes"); n != 1 {
		t.Errorf("oauth2_codes = %d, want 1 (code preserved)", n)
	}
}

func TestTokenHandler_Confidential_MissingSecret(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")

	form := url.Values{"client_id": {"web"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")
}

// --- NEW FLOW: public client + PKCE ---

func TestTokenHandler_Public_PKCE_Success(t *testing.T) {
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
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access_token must be populated")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.ExpiresIn != tokenTTLSeconds {
		t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, tokenTTLSeconds)
	}
	if email, ok := tokenEmail(t, ctx, hashToken(resp.AccessToken)); !ok || email != "user@example.com" {
		t.Errorf("persisted token email = %q (ok=%v), want user@example.com", email, ok)
	}
}

func TestTokenHandler_Public_PKCE_BadVerifier(t *testing.T) {
	t.Parallel()
	_, challenge := pkcePair()
	const redirect = "http://127.0.0.1:5000/callback"

	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", redirect)
	seedCode(t, ctx, "abc", "cli", "user@example.com", challenge, "S256", redirect, "")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"code":          {"abc"},
		"code_verifier": {"this-is-the-wrong-verifier"},
		"redirect_uri":  {redirect},
	}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")
	if n := countRows(t, ctx, "user_tokens"); n != 0 {
		t.Errorf("user_tokens = %d, want 0 (no token issued on PKCE failure)", n)
	}
}

func TestTokenHandler_Public_RedirectMismatch(t *testing.T) {
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
		"redirect_uri":  {"http://127.0.0.1:5000/different"},
	}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

func TestTokenHandler_Public_MissingVerifier(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:5000/callback")

	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"cli"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")
}

// --- shared request validation ---

func TestTokenHandler_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	form := url.Values{"grant_type": {"password"}, "client_id": {"x"}, "code": {"y"}}
	rec := httptest.NewRecorder()
	// Rejected before any DB access.
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "unsupported_grant_type")
}

func TestTokenHandler_UnknownClient(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx() // empty DB: client lookup misses

	form := url.Values{"client_id": {"ghost"}, "client_secret": {"x"}, "code": {"y"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_client")
}

func TestTokenHandler_InvalidCode(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")

	form := url.Values{"client_id": {"web"}, "client_secret": {"topsecret"}, "code": {"gone"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, postForm(t, "/token", form).WithContext(ctx))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

func assertOAuthError(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Error != wantCode {
		t.Errorf("error = %q, want %q", body.Error, wantCode)
	}
}
