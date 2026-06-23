package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/acoshift/pgsql/pgctx"
)

// clientFlags reads the lifecycle columns of a client row.
func clientFlags(t *testing.T, ctx context.Context, id string) (dyn bool, lastUsed sql.NullTime, ok bool) {
	t.Helper()
	err := pgctx.QueryRow(ctx,
		`select dynamically_registered, last_used_at from oauth2_clients where id = $1`, id,
	).Scan(&dyn, &lastUsed)
	if err != nil {
		return false, sql.NullTime{}, false
	}
	return dyn, lastUsed, true
}

func clientExists(t *testing.T, ctx context.Context, id string) bool {
	t.Helper()
	var n int
	if err := pgctx.QueryRow(ctx, `select count(*) from oauth2_clients where id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count client %q: %v", id, err)
	}
	return n > 0
}

// The migration seeds the well-known public CLI client as a non-DCR row.
func TestSeedCLIClientPresent(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()

	if !clientExists(t, ctx, "deploys-cli") {
		t.Fatal("deploys-cli client was not seeded by the migration")
	}
	dyn, _, ok := clientFlags(t, ctx, "deploys-cli")
	if !ok {
		t.Fatal("deploys-cli flags not readable")
	}
	if dyn {
		t.Error("seeded deploys-cli must NOT be dynamically_registered (would make it GC-eligible)")
	}
	uris, ok := clientRedirectURIs(t, ctx, "deploys-cli")
	if !ok || len(uris) != 1 || uris[0] != "http://127.0.0.1/callback" {
		t.Errorf("deploys-cli redirect_uris = %v", uris)
	}
	// And it must be a public client (PKCE, no secret).
	var method string
	if err := pgctx.QueryRow(ctx, `select token_endpoint_auth_method from oauth2_clients where id='deploys-cli'`).Scan(&method); err != nil {
		t.Fatal(err)
	}
	if method != "none" {
		t.Errorf("deploys-cli auth method = %q; want none", method)
	}
}

// A DCR registration is marked dynamically_registered so GC may reap it.
func TestRegisterMarksDynamicallyRegistered(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()

	rec := httptest.NewRecorder()
	body := `{"client_name":"cli","redirect_uris":["http://127.0.0.1/callback"]}`
	RegisterHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, postJSON(t, "/register", body).WithContext(ctx))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	dyn, _, ok := clientFlags(t, ctx, resp.ClientID)
	if !ok {
		t.Fatal("registered client not found")
	}
	if !dyn {
		t.Error("DCR client must be marked dynamically_registered")
	}
}

// Authorize stamps last_used_at so GC reaps by idle time.
func TestRedirectStampsLastUsed(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()

	// deploys-cli is seeded; its port-less loopback redirect matches any port.
	_, challenge := pkcePair()
	q := url.Values{}
	q.Set("client_id", "deploys-cli")
	q.Set("state", "cbstate")
	q.Set("redirect_uri", "http://127.0.0.1:5555/callback")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?"+q.Encode(), nil).WithContext(ctx)
	RedirectHandler{OAuth2ClientID: "google-client", BaseURL: "https://auth.test"}.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, lastUsed, ok := clientFlags(t, ctx, "deploys-cli")
	if !ok {
		t.Fatal("client not found")
	}
	if !lastUsed.Valid {
		t.Error("authorize did not stamp last_used_at")
	}
}

// GC reaps only idle DCR clients; fresh DCR and all non-DCR clients survive.
func TestCleanupReapsIdleDCRClients(t *testing.T) {
	t.Parallel()
	tdb := newTestDB(t)
	ctx := tdb.Ctx()

	old := time.Now().Add(-100 * 24 * time.Hour)
	seed := func(id string, dcr bool, lastUsed *time.Time, createdAgo time.Duration) {
		created := time.Now().Add(-createdAgo)
		_, err := pgctx.Exec(ctx, `
			insert into oauth2_clients (id, secret, redirect_uris, token_endpoint_auth_method, client_name, dynamically_registered, created_at, last_used_at)
			values ($1, null, array['http://127.0.0.1/callback'], 'none', $1, $2, $3, $4)
		`, id, dcr, created, lastUsed)
		if err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("idle-dcr", true, &old, 0) // reaped: idle past TTL
	now := time.Now()
	seed("fresh-dcr", true, &now, 0)                    // kept: recently used
	seed("never-used-dcr", true, nil, 100*24*time.Hour) // reaped: null last_used, old created_at
	seed("old-seeded", false, &old, 0)                  // kept: not DCR

	cleanupExpired(tdb.DB)

	for _, id := range []string{"fresh-dcr", "old-seeded", "deploys-cli"} {
		if !clientExists(t, ctx, id) {
			t.Errorf("client %q should have survived GC", id)
		}
	}
	for _, id := range []string{"idle-dcr", "never-used-dcr"} {
		if clientExists(t, ctx, id) {
			t.Errorf("idle DCR client %q should have been reaped", id)
		}
	}
}

func TestRegisterLimiter(t *testing.T) {
	t.Parallel()
	// Construct the struct directly to avoid starting the sweep goroutine.
	l := &registerLimiter{hits: map[string][]time.Time{}, max: 2, window: time.Hour}
	if !l.allow("1.2.3.4") || !l.allow("1.2.3.4") {
		t.Fatal("first two hits should be allowed")
	}
	if l.allow("1.2.3.4") {
		t.Error("third hit within window should be denied")
	}
	// A different key is independent.
	if !l.allow("5.6.7.8") {
		t.Error("a different IP should not be limited")
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		xff, remote, want string
	}{
		{"", "1.2.3.4:55555", "1.2.3.4"},
		{"9.9.9.9", "1.2.3.4:5", "9.9.9.9"},
		// Rightmost (proxy-appended) entry wins, not the spoofable leftmost.
		{"9.9.9.9, 10.0.0.1", "1.2.3.4:5", "10.0.0.1"},
		{"9.9.9.9 , 10.0.0.1 ", "1.2.3.4:5", "10.0.0.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/register", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("clientIP(xff=%q remote=%q) = %q; want %q", c.xff, c.remote, got, c.want)
		}
	}
}
