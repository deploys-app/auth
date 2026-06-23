package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postJSON(t *testing.T, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestRegisterHandler_Success(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()

	body := `{"client_name":"my cli","redirect_uris":["http://127.0.0.1:1234/cb"]}`
	rec := httptest.NewRecorder()
	RegisterHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, postJSON(t, "/register", body).WithContext(ctx))

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
		t.Fatal("client_id is empty")
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q, want none", resp.TokenEndpointAuthMethod)
	}
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "http://127.0.0.1:1234/cb" {
		t.Errorf("redirect_uris = %v", resp.RedirectURIs)
	}
	// The client is persisted as a public client with the registered redirect.
	if uris, ok := clientRedirectURIs(t, ctx, resp.ClientID); !ok || len(uris) != 1 || uris[0] != "http://127.0.0.1:1234/cb" {
		t.Errorf("persisted redirect_uris = %v (ok=%v)", uris, ok)
	}
}

func TestRegisterHandler_HTTPSRedirectAllowed(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()

	body := `{"redirect_uris":["https://app.example.com/cb"]}`
	rec := httptest.NewRecorder()
	RegisterHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, postJSON(t, "/register", body).WithContext(ctx))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	// One client from this registration, plus the seeded deploys-cli fixture the
	// migration always installs.
	if n := countRows(t, ctx, "oauth2_clients"); n != 2 {
		t.Errorf("oauth2_clients = %d, want 2 (1 registered + seeded deploys-cli)", n)
	}
}

func TestRegisterHandler_Rejections(t *testing.T) {
	t.Parallel()
	// All rejected before any DB write, so no test DB is needed.
	cases := map[string]string{
		"invalid json":            `{not json`,
		"no redirect_uris":        `{"client_name":"x"}`,
		"non-loopback http":       `{"redirect_uris":["http://app.example.com/cb"]}`,
		"confidential rejected":   `{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
		"regexp pattern rejected": `{"redirect_uris":["regexp:https://*.example.com/cb"]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			RegisterHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, postJSON(t, "/register", body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
