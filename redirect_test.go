package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("web", "topsecret", "https://app.example.com/*", "", "client_secret_post"))
	mock.ExpectExec("insert into oauth2_sessions").WillReturnResult(sqlmock.NewResult(0, 1))

	q := url.Values{
		"client_id":    {"web"},
		"state":        {"cbstate"},
		"redirect_uri": {"https://app.example.com/cb"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "googleclient", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(getReq(t, q), db))

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
	if c := findCookie(rec, "s"); c == nil || c.Value == "" {
		t.Error("session cookie 's' not set")
	}
	assertExpectations(t, mock)
}

func TestRedirectHandler_MissingParams(t *testing.T) {
	cases := map[string]url.Values{
		"missing client_id":    {"state": {"s"}, "redirect_uri": {"https://a/cb"}},
		"missing state":        {"client_id": {"web"}, "redirect_uri": {"https://a/cb"}},
		"missing redirect_uri": {"client_id": {"web"}, "state": {"s"}},
		"invalid redirect_uri": {"client_id": {"web"}, "state": {"s"}, "redirect_uri": {"not-a-url"}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			db, _ := newMock(t) // no DB calls expected
			rec := httptest.NewRecorder()
			RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
				ServeHTTP(rec, withDB(getReq(t, q), db))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestRedirectHandler_UnknownClient(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").WillReturnError(sqlNoRows())

	q := url.Values{"client_id": {"ghost"}, "state": {"s"}, "redirect_uri": {"https://a/cb"}}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(getReq(t, q), db))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRedirectHandler_Confidential_RedirectNotAllowed(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("web", "topsecret", "https://app.example.com/*", "", "client_secret_post"))

	q := url.Values{"client_id": {"web"}, "state": {"s"}, "redirect_uri": {"https://evil.example.com/cb"}}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(getReq(t, q), db))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// --- NEW FLOW: public client requires PKCE + exact (loopback) redirect ---

func TestRedirectHandler_Public_Success(t *testing.T) {
	_, challenge := pkcePair()
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", "http://127.0.0.1:1234/callback", "none"))
	// PKCE challenge + method must be persisted on the session for the callback.
	mock.ExpectExec("insert into oauth2_sessions").
		WithArgs(sqlmock.AnyArg(), "cli", sqlmock.AnyArg(), "cbstate",
			"http://127.0.0.1:55001/callback", challenge, "S256", "").
		WillReturnResult(sqlmock.NewResult(0, 1))

	q := url.Values{
		"client_id":             {"cli"},
		"state":                 {"cbstate"},
		"redirect_uri":          {"http://127.0.0.1:55001/callback"}, // different loopback port, allowed
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "googleclient", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(getReq(t, q), db))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://accounts.google.com/") {
		t.Errorf("Location = %q", rec.Header().Get("Location"))
	}
	assertExpectations(t, mock)
}

func TestRedirectHandler_Public_MissingChallenge(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", "http://127.0.0.1:1234/callback", "none"))

	q := url.Values{"client_id": {"cli"}, "state": {"s"}, "redirect_uri": {"http://127.0.0.1:55001/callback"}}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(getReq(t, q), db))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (PKCE required for public clients)", rec.Code)
	}
}

func TestRedirectHandler_Public_UnsupportedChallengeMethod(t *testing.T) {
	_, challenge := pkcePair()
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", "http://127.0.0.1:1234/callback", "none"))

	q := url.Values{
		"client_id":             {"cli"},
		"state":                 {"s"},
		"redirect_uri":          {"http://127.0.0.1:55001/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"plain"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(getReq(t, q), db))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (only S256)", rec.Code)
	}
}

func TestRedirectHandler_Public_RedirectNotRegistered(t *testing.T) {
	_, challenge := pkcePair()
	db, mock := newMock(t)
	mock.ExpectQuery("from oauth2_clients").
		WillReturnRows(clientRow("cli", "", "", "http://127.0.0.1:1234/callback", "none"))

	q := url.Values{
		"client_id":             {"cli"},
		"state":                 {"s"},
		"redirect_uri":          {"https://evil.example.com/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	RedirectHandler{OAuth2ClientID: "g", BaseURL: "https://auth.test"}.
		ServeHTTP(rec, withDB(getReq(t, q), db))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (redirect not registered)", rec.Code)
	}
}
