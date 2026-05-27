package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func postJSON(t *testing.T, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestRegisterHandler_Success(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec("insert into oauth2_clients").
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"client_name":"my cli","redirect_uris":["http://127.0.0.1:1234/cb"]}`
	rec := httptest.NewRecorder()
	RegisterHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, withDB(postJSON(t, "/register", body), db))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ClientID                string   `json:"client_id"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		RedirectURIs            []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ClientID == "" {
		t.Error("client_id is empty")
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q, want none", resp.TokenEndpointAuthMethod)
	}
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "http://127.0.0.1:1234/cb" {
		t.Errorf("redirect_uris = %v", resp.RedirectURIs)
	}
	assertExpectations(t, mock)
}

func TestRegisterHandler_HTTPSRedirectAllowed(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec("insert into oauth2_clients").WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"redirect_uris":["https://app.example.com/cb"]}`
	rec := httptest.NewRecorder()
	RegisterHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, withDB(postJSON(t, "/register", body), db))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	assertExpectations(t, mock)
}

func TestRegisterHandler_Rejections(t *testing.T) {
	cases := map[string]string{
		"invalid json":          `{not json`,
		"no redirect_uris":      `{"client_name":"x"}`,
		"non-loopback http":     `{"redirect_uris":["http://app.example.com/cb"]}`,
		"confidential rejected": `{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			db, _ := newMock(t) // no insert expected
			rec := httptest.NewRecorder()
			RegisterHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, withDB(postJSON(t, "/register", body), db))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
