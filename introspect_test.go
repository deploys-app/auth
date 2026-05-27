package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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
	db, _ := newMock(t)
	rec := httptest.NewRecorder()
	IntrospectHandler{Token: ""}.ServeHTTP(rec, withDB(introspectReq(t, "Bearer x", "tok"), db))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestIntrospectHandler_Unauthorized(t *testing.T) {
	db, _ := newMock(t)
	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, withDB(introspectReq(t, "Bearer wrong", "tok"), db))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIntrospectHandler_ActiveToken(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from user_tokens").
		WillReturnRows(sqlmock.NewRows([]string{"email", "exp"}).AddRow("user@example.com", int64(1893456000)))

	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, withDB(introspectReq(t, "Bearer secret", "deploys-api.abc"), db))

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
	if resp.Exp != 1893456000 {
		t.Errorf("exp = %d", resp.Exp)
	}
	assertExpectations(t, mock)
}

func TestIntrospectHandler_UnknownToken(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from user_tokens").WillReturnError(sqlNoRows())

	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, withDB(introspectReq(t, "Bearer secret", "deploys-api.gone"), db))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Error("active = true, want false for unknown token")
	}
	assertExpectations(t, mock)
}

func TestIntrospectHandler_EmptyToken(t *testing.T) {
	db, _ := newMock(t) // no DB lookup for empty token
	rec := httptest.NewRecorder()
	IntrospectHandler{Token: "secret"}.ServeHTTP(rec, withDB(introspectReq(t, "Bearer secret", ""), db))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Active bool `json:"active"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Active {
		t.Error("active = true, want false for empty token")
	}
}
