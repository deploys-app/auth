package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func introspectReq(t *testing.T, auth, token string) *http.Request {
	t.Helper()
	form := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return req
}

func TestIntrospectHandler_NotConfigured(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	IntrospectHandler{Token: ""}.ServeHTTP(rec, introspectReq(t, "Bearer x", "tok"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestIntrospectHandler_Unauthorized(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, introspectReq(t, "Bearer wrong", "tok"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIntrospectHandler_ActiveToken(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	const raw = "deploys-api.abc"
	seedToken(t, ctx, hashToken(raw), "user@example.com")

	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, introspectReq(t, "Bearer secret", raw).WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Active bool   `json:"active"`
		Sub    string `json:"sub"`
		Exp    int64  `json:"exp"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Active {
		t.Error("active = false, want true")
	}
	if resp.Sub != "user@example.com" {
		t.Errorf("sub = %q", resp.Sub)
	}
	if resp.Exp == 0 {
		t.Error("exp = 0, want a future unix timestamp")
	}
}

func TestIntrospectHandler_UnknownToken(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx() // empty user_tokens

	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, introspectReq(t, "Bearer secret", "deploys-api.gone").WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if active := decodeActive(t, rec); active {
		t.Error("active = true, want false for unknown token")
	}
}

func TestIntrospectHandler_ExpiredToken(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	const raw = "deploys-api.expired"
	// Insert a token that already expired.
	if _, err := pgctxExec(t, ctx, `insert into user_tokens (token, email, expires_at) values ($1, $2, now() - interval '1 hour')`, hashToken(raw), "old@example.com"); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, introspectReq(t, "Bearer secret", raw).WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if active := decodeActive(t, rec); active {
		t.Error("active = true, want false for expired token")
	}
}

func TestIntrospectHandler_EmptyToken(t *testing.T) {
	t.Parallel()
	// Empty token short-circuits before any DB lookup.
	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, introspectReq(t, "Bearer secret", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if active := decodeActive(t, rec); active {
		t.Error("active = true, want false for empty token")
	}
}

func decodeActive(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	var resp struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Active
}
