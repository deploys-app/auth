package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// A single mock Google token endpoint is started lazily and shared by all
// callback tests. It keys the returned id_token email by the authorization
// code in the request, so parallel tests do not race over googleTokenURL.
var (
	googleMockOnce sync.Once
	googleMockMap  sync.Map // code -> email
)

func registerGoogleCode(t *testing.T, code, email string) {
	t.Helper()
	googleMockOnce.Do(func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			email := "default@example.com"
			if v, ok := googleMockMap.Load(r.FormValue("code")); ok {
				email = v.(string)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id_token":%q}`, fakeIDToken(email))
		}))
		googleTokenURL = srv.URL
	})
	googleMockMap.Store(code, email)
	t.Cleanup(func() { googleMockMap.Delete(code) })
}

// --- OLD FLOW (regression): Google callback issues an internal code ---

func TestCallbackHandler_Confidential_Success(t *testing.T) {
	t.Parallel()
	registerGoogleCode(t, t.Name(), "user@example.com")

	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedConfidentialClient(t, ctx, "web", "topsecret", "https://app.example.com/cb")
	seedSession(t, ctx, "sess123", "web", "gstate", "cbstate", "https://app.example.com/cb", "", "", "")

	q := url.Values{"state": {"gstate"}, "code": {t.Name()}}
	req := getReqPath(t, "/callback", q)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sess123"})
	rec := httptest.NewRecorder()
	CallbackHandler{OAuth2ClientID: "g", OAuth2ClientSecret: "gs", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/cb?") {
		t.Fatalf("Location = %q, want redirect to client callback", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") != "cbstate" {
		t.Errorf("callback state = %q, want cbstate", u.Query().Get("state"))
	}
	returnedCode := u.Query().Get("code")
	if returnedCode == "" {
		t.Fatal("callback code is empty")
	}
	// The session is single-use and an internal code was minted for the email.
	if n := countRows(t, ctx, "oauth2_sessions"); n != 0 {
		t.Errorf("oauth2_sessions = %d, want 0 (consumed)", n)
	}
	email, challenge, method := codeEmailPKCE(t, ctx, returnedCode)
	if email != "user@example.com" {
		t.Errorf("code email = %q, want user@example.com", email)
	}
	if challenge != "" || method != "" {
		t.Errorf("confidential code carried PKCE: (%q,%q)", challenge, method)
	}
}

func TestCallbackHandler_MissingSessionCookie(t *testing.T) {
	t.Parallel()
	q := url.Values{"state": {"gstate"}, "code": {"google-code"}}
	req := getReqPath(t, "/callback", q) // no cookie
	rec := httptest.NewRecorder()
	CallbackHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackHandler_StateMismatch(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedSession(t, ctx, "sess123", "web", "expected-state", "cbstate", "https://app.example.com/cb", "", "", "")

	q := url.Values{"state": {"attacker-state"}, "code": {"google-code"}}
	req := getReqPath(t, "/callback", q)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sess123"})
	rec := httptest.NewRecorder()
	CallbackHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (state mismatch)", rec.Code)
	}
	// Session is consumed on read even on mismatch; no code should be minted.
	if n := countRows(t, ctx, "oauth2_codes"); n != 0 {
		t.Errorf("oauth2_codes = %d, want 0", n)
	}
}

// --- NEW FLOW: PKCE challenge from the session is carried onto the code ---

func TestCallbackHandler_Public_CarriesPKCE(t *testing.T) {
	t.Parallel()
	registerGoogleCode(t, t.Name(), "user@example.com")
	_, challenge := pkcePair()

	tdb := newTestDB(t)
	ctx := tdb.Ctx()
	seedPublicClient(t, ctx, "cli", "http://127.0.0.1:55001/callback")
	seedSession(t, ctx, "sess123", "cli", "gstate", "cbstate", "http://127.0.0.1:55001/callback", challenge, "S256", "https://api.deploys.app")

	q := url.Values{"state": {"gstate"}, "code": {t.Name()}}
	req := getReqPath(t, "/callback", q)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sess123"})
	rec := httptest.NewRecorder()
	CallbackHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	email, gotChallenge, gotMethod := codeEmailPKCE(t, ctx, u.Query().Get("code"))
	if email != "user@example.com" {
		t.Errorf("code email = %q", email)
	}
	if gotChallenge != challenge || gotMethod != "S256" {
		t.Errorf("code PKCE = (%q,%q), want (%q,S256)", gotChallenge, gotMethod, challenge)
	}
}

func getReqPath(t *testing.T, path string, q url.Values) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
}
