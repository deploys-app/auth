package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func getReq(t *testing.T, q url.Values) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, "/?"+q.Encode(), nil)
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// --- OLD FLOW (regression): confidential client redirect to Google ---

func TestRedirectHandler_Confidential_Success(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")

	q := url.Values{
		"client_id":    {"web"},
		"state":        {"cbstate"},
		"redirect_uri": {"https://app.example.com/cb"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "googleclient", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, getReq(t, q).WithContext(ctx))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://accounts.google.com/o/oauth2/auth?") {
		t.Errorf("Location = %q, want Google authorize URL", loc)
	}
	if !strings.Contains(loc, "client_id=googleclient") {
		t.Errorf("Location missing google client_id: %q", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("https://auth.test/callback")) {
		t.Errorf("Location missing callback redirect_uri: %q", loc)
	}
	if !strings.Contains(loc, "prompt=select_account") {
		t.Errorf("Location missing prompt=select_account (avoids the extra consent screen): %q", loc)
	}
	if c := findCookie(rec, "s"); c == nil || c.Value == "" {
		t.Error("session cookie 's' not set")
	}
	if n := countRows(t, ctx, "oauth2_sessions"); n != 1 {
		t.Errorf("oauth2_sessions = %d, want 1", n)
	}
}

func TestRedirectHandler_MissingParams(t *testing.T) {
	t.Parallel()
	// All rejected before any DB access, so no test DB is needed.
	cases := map[string]url.Values{
		"missing client_id":    {"state": {"s"}, "redirect_uri": {"https://a/cb"}},
		"missing state":        {"client_id": {"web"}, "redirect_uri": {"https://a/cb"}},
		"missing redirect_uri": {"client_id": {"web"}, "state": {"s"}},
		"invalid redirect_uri": {"client_id": {"web"}, "state": {"s"}, "redirect_uri": {"not-a-url"}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.ServeHTTP(rec, getReq(t, q))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestRedirectHandler_UnknownClient(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx() // empty DB

	q := url.Values{"client_id": {"ghost"}, "state": {"s"}, "redirect_uri": {"https://a/cb"}}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, getReq(t, q).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRedirectHandler_Confidential_RedirectNotAllowed(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")

	q := url.Values{"client_id": {"web"}, "state": {"s"}, "redirect_uri": {"https://evil.example.com/cb"}}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, getReq(t, q).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestRedirectHandler_RegexpRedirect exercises an operator-provisioned "regexp:"
// redirect_uris entry end to end (the PR-preview use case): a bounded pattern
// that matches dynamic preview hosts but not arbitrary subdomains.
func TestRedirectHandler_RegexpRedirect(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "preview", "topsecret",
		`regexp:https://console-pr-\d+-606515731026706458.rcf2.deploys.app/auth/callback`)

	cases := map[string]struct {
		redirect string
		want     int
	}{
		"matching preview host":   {"https://console-pr-42-606515731026706458.rcf2.deploys.app/auth/callback", http.StatusFound},
		"non-digit pr id":         {"https://console-pr-abc-606515731026706458.rcf2.deploys.app/auth/callback", http.StatusBadRequest},
		"different account zone":  {"https://console-pr-42-999999999999999999.rcf2.deploys.app/auth/callback", http.StatusBadRequest},
		"arbitrary subdomain":     {"https://evil.rcf2.deploys.app/auth/callback", http.StatusBadRequest},
		"dot is literal not wild": {"https://console-pr-42-606515731026706458Xrcf2.deploys.app/auth/callback", http.StatusBadRequest},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			q := url.Values{"client_id": {"preview"}, "state": {"s"}, "redirect_uri": {c.redirect}}
			rec := httptest.NewRecorder()
			RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
				ServeHTTP(rec, getReq(t, q).WithContext(ctx))
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

// --- NEW FLOW: public client requires PKCE + exact (loopback) redirect ---

func TestRedirectHandler_Public_Success(t *testing.T) {
	t.Parallel()
	_, challenge := pkcePair()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:1234/callback")

	q := url.Values{
		"client_id":             {"cli"},
		"state":                 {"cbstate"},
		"redirect_uri":          {"http://127.0.0.1:55001/callback"}, // different loopback port, allowed
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "googleclient", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, getReq(t, q).WithContext(ctx))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://accounts.google.com/") {
		t.Errorf("Location = %q", rec.Header().Get("Location"))
	}
	// The PKCE challenge must be persisted on the session for the callback.
	challengeStored, methodStored, cbURL := oneSessionPKCE(t, ctx)
	if challengeStored != challenge || methodStored != "S256" {
		t.Errorf("session PKCE = (%q,%q), want (%q,S256)", challengeStored, methodStored, challenge)
	}
	if cbURL != "http://127.0.0.1:55001/callback" {
		t.Errorf("session callback_url = %q", cbURL)
	}
}

func TestRedirectHandler_Public_MissingChallenge(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:1234/callback")

	q := url.Values{"client_id": {"cli"}, "state": {"s"}, "redirect_uri": {"http://127.0.0.1:55001/callback"}}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, getReq(t, q).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (PKCE required for public clients)", rec.Code)
	}
}

func TestRedirectHandler_Public_UnsupportedChallengeMethod(t *testing.T) {
	t.Parallel()
	_, challenge := pkcePair()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:1234/callback")

	q := url.Values{
		"client_id":             {"cli"},
		"state":                 {"s"},
		"redirect_uri":          {"http://127.0.0.1:55001/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"plain"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, getReq(t, q).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (only S256)", rec.Code)
	}
}

func TestRedirectHandler_Public_RedirectNotRegistered(t *testing.T) {
	t.Parallel()
	_, challenge := pkcePair()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:1234/callback")

	q := url.Values{
		"client_id":             {"cli"},
		"state":                 {"s"},
		"redirect_uri":          {"https://evil.example.com/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, getReq(t, q).WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (redirect not registered)", rec.Code)
	}
}
