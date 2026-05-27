package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func sessionRow(clientID, state, callbackState, callbackURL, challenge, method, resource string) *sqlmock.Rows {
	cols := []string{"client_id", "state", "callback_state", "callback_url", "code_challenge", "code_challenge_method", "resource"}
	return sqlmock.NewRows(cols).AddRow(clientID, state, callbackState, callbackURL, challenge, method, resource)
}

// stubGoogle points the callback token exchange at a local server that returns
// an id_token carrying email, and restores the real URL afterwards.
func stubGoogle(t *testing.T, email string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id_token":%q}`, fakeIDToken(email))
	}))
	old := googleTokenURL
	googleTokenURL = srv.URL
	t.Cleanup(func() {
		googleTokenURL = old
		srv.Close()
	})
}

// --- OLD FLOW (regression): Google callback issues an internal code ---

func TestCallbackHandler_Confidential_Success(t *testing.T) {
	stubGoogle(t, "user@example.com")

	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_sessions").
		WillReturnRows(sessionRow("web", "gstate", "cbstate", "https://app.example.com/cb", "", "", ""))
	mock.ExpectExec("delete from oauth2_sessions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("insert into oauth2_codes").
		WithArgs(sqlmock.AnyArg(), "web", "user@example.com", "", "", "https://app.example.com/cb", "").
		WillReturnResult(sqlmock.NewResult(0, 1))

	q := url.Values{"state": {"gstate"}, "code": {"google-code"}}
	req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sess123"})
	rec := httptest.NewRecorder()
	CallbackHandler{OAuth2ClientID: "g", OAuth2ClientSecret: "gs", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(req, db))

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
	if u.Query().Get("code") == "" {
		t.Error("callback code is empty")
	}
	assertExpectations(t, mock)
}

func TestCallbackHandler_MissingSessionCookie(t *testing.T) {
	db, _ := newMock(t)
	q := url.Values{"state": {"gstate"}, "code": {"google-code"}}
	req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil) // no cookie
	rec := httptest.NewRecorder()
	CallbackHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, withDB(req, db))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackHandler_StateMismatch(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_sessions").
		WillReturnRows(sessionRow("web", "expected-state", "cbstate", "https://app.example.com/cb", "", "", ""))
	mock.ExpectExec("delete from oauth2_sessions").WillReturnResult(sqlmock.NewResult(0, 1))

	q := url.Values{"state": {"attacker-state"}, "code": {"google-code"}}
	req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sess123"})
	rec := httptest.NewRecorder()
	CallbackHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, withDB(req, db))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (state mismatch)", rec.Code)
	}
	assertExpectations(t, mock)
}

// --- NEW FLOW: PKCE challenge from the session is carried onto the code ---

func TestCallbackHandler_Public_CarriesPKCE(t *testing.T) {
	stubGoogle(t, "user@example.com")
	_, challenge := pkcePair()

	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_sessions").
		WillReturnRows(sessionRow("cli", "gstate", "cbstate", "http://127.0.0.1:55001/callback", challenge, "S256", "https://api.deploys.app"))
	mock.ExpectExec("delete from oauth2_sessions").WillReturnResult(sqlmock.NewResult(0, 1))
	// The code must be persisted with the PKCE challenge, redirect and resource.
	mock.ExpectExec("insert into oauth2_codes").
		WithArgs(sqlmock.AnyArg(), "cli", "user@example.com", challenge, "S256", "http://127.0.0.1:55001/callback", "https://api.deploys.app").
		WillReturnResult(sqlmock.NewResult(0, 1))

	q := url.Values{"state": {"gstate"}, "code": {"google-code"}}
	req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sess123"})
	rec := httptest.NewRecorder()
	CallbackHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, withDB(req, db))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	assertExpectations(t, mock)
}
