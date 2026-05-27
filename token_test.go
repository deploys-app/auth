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

func postForm(t *testing.T, path string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func clientRow(id, secret, redirectURI, redirectURIs, authMethod string) *sqlmock.Rows {
	cols := []string{"id", "secret", "redirect_uri", "redirect_uris", "token_endpoint_auth_method"}
	var sec any = secret
	if secret == "" && authMethod == "none" {
		sec = nil // public clients store NULL secret
	}
	return sqlmock.NewRows(cols).AddRow(id, sec, redirectURI, redirectURIs, authMethod)
}

func codeRow(email, challenge, method, redirectURI, resource string) *sqlmock.Rows {
	cols := []string{"email", "code_challenge", "code_challenge_method", "redirect_uri", "resource"}
	return sqlmock.NewRows(cols).AddRow(email, challenge, method, redirectURI, resource)
}

// --- OLD FLOW (regression): confidential client + client_secret ---

func TestTokenHandler_Confidential_Success(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("web", "topsecret", "https://app.example.com/*", "", "client_secret_post"))
	mock.ExpectQuery("delete from oauth2_codes").
		WillReturnRows(codeRow("user@example.com", "", "", "https://app.example.com/cb", ""))
	mock.ExpectExec("insert into user_tokens").
		WithArgs(sqlmock.AnyArg(), "user@example.com").
		WillReturnResult(sqlmock.NewResult(0, 1))

	form := url.Values{"client_id": {"web"}, "client_secret": {"topsecret"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

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
	if resp.RefreshToken == "" {
		t.Error("refresh_token must remain populated for the legacy client")
	}
	if !strings.HasPrefix(resp.RefreshToken, tokenPrefix) {
		t.Errorf("refresh_token %q missing prefix %q", resp.RefreshToken, tokenPrefix)
	}
	// New fields for OAuth2.1 clients.
	if resp.AccessToken != resp.RefreshToken {
		t.Errorf("access_token (%q) should equal refresh_token (%q)", resp.AccessToken, resp.RefreshToken)
	}
	if resp.ExpiresIn != tokenTTLSeconds {
		t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, tokenTTLSeconds)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	assertExpectations(t, mock)
}

func TestTokenHandler_Confidential_WrongSecret(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("web", "topsecret", "https://app.example.com/*", "", "client_secret_post"))

	form := url.Values{"client_id": {"web"}, "client_secret": {"wrong"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_client")
	assertExpectations(t, mock)
}

func TestTokenHandler_Confidential_MissingSecret(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("web", "topsecret", "https://app.example.com/*", "", "client_secret_post"))

	form := url.Values{"client_id": {"web"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")
}

// --- NEW FLOW: public client + PKCE ---

func TestTokenHandler_Public_PKCE_Success(t *testing.T) {
	verifier, challenge := pkcePair()
	const redirect = "http://127.0.0.1:5000/callback"

	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", redirect, "none"))
	mock.ExpectQuery("delete from oauth2_codes").
		WillReturnRows(codeRow("user@example.com", challenge, "S256", redirect, ""))
	mock.ExpectExec("insert into user_tokens").
		WithArgs(sqlmock.AnyArg(), "user@example.com").
		WillReturnResult(sqlmock.NewResult(0, 1))

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"code":          {"abc"},
		"code_verifier": {verifier},
		"redirect_uri":  {redirect},
	}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

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
	assertExpectations(t, mock)
}

func TestTokenHandler_Public_PKCE_BadVerifier(t *testing.T) {
	_, challenge := pkcePair()
	const redirect = "http://127.0.0.1:5000/callback"

	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", redirect, "none"))
	mock.ExpectQuery("delete from oauth2_codes").
		WillReturnRows(codeRow("user@example.com", challenge, "S256", redirect, ""))

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"code":          {"abc"},
		"code_verifier": {"this-is-the-wrong-verifier"},
		"redirect_uri":  {redirect},
	}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")
	assertExpectations(t, mock)
}

func TestTokenHandler_Public_RedirectMismatch(t *testing.T) {
	verifier, challenge := pkcePair()

	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", "http://127.0.0.1:5000/callback", "none"))
	mock.ExpectQuery("delete from oauth2_codes").
		WillReturnRows(codeRow("user@example.com", challenge, "S256", "http://127.0.0.1:5000/callback", ""))

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"code":          {"abc"},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://127.0.0.1:5000/different"},
	}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
	assertExpectations(t, mock)
}

func TestTokenHandler_Public_MissingVerifier(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", "http://127.0.0.1:5000/callback", "none"))

	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"cli"}, "code": {"abc"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")
	assertExpectations(t, mock)
}

// --- shared request validation ---

func TestTokenHandler_UnsupportedGrantType(t *testing.T) {
	db, _ := newMock(t)
	form := url.Values{"grant_type": {"password"}, "client_id": {"x"}, "code": {"y"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "unsupported_grant_type")
}

func TestTokenHandler_UnknownClient(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").WillReturnError(sqlNoRows())

	form := url.Values{"client_id": {"ghost"}, "client_secret": {"x"}, "code": {"y"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_client")
}

func TestTokenHandler_InvalidCode(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("web", "topsecret", "https://app.example.com/*", "", "client_secret_post"))
	mock.ExpectQuery("delete from oauth2_codes").WillReturnError(sqlNoRows())

	form := url.Values{"client_id": {"web"}, "client_secret": {"topsecret"}, "code": {"gone"}}
	rec := httptest.NewRecorder()
	TokenHandler{}.ServeHTTP(rec, withDB(postForm(t, "/token", form), db))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
	assertExpectations(t, mock)
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
