package main

import (
	"database/sql"
	"net/http"
	"os"
	"strings"

	"github.com/acoshift/pgsql/pgctx"
	_ "github.com/lib/pq"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "https://auth.deploys.app"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	oauth2ClientID := os.Getenv("OAUTH2_CLIENT_ID")
	if oauth2ClientID == "" {
		panic("missing OAUTH2_CLIENT_ID")
	}
	oauth2ClientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")

	introspectionToken := os.Getenv("INTROSPECTION_TOKEN")

	sqlURL := os.Getenv("SQL_URL")
	if sqlURL == "" {
		panic("missing SQL_URL")
	}
	db, err := sql.Open("postgres", sqlURL)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	startCleanupWorker(db)

	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/oauth-authorization-server", MetadataHandler{BaseURL: baseURL})
	mux.Handle("GET /", RedirectHandler{OAuth2ClientID: oauth2ClientID, BaseURL: baseURL})
	mux.Handle("GET /callback", CallbackHandler{
		OAuth2ClientID:     oauth2ClientID,
		OAuth2ClientSecret: oauth2ClientSecret,
		BaseURL:            baseURL,
	})
	mux.Handle("GET /revoke", RevokeHandler{}) // TODO: remove ?
	mux.Handle("POST /revoke", RevokePostHandler{})
	mux.Handle("POST /token", TokenHandler{})
	mux.Handle("POST /register", RegisterHandler{BaseURL: baseURL})
	mux.Handle("POST /introspect", IntrospectHandler{Token: introspectionToken})

	http.ListenAndServe(":"+port, pgctx.Middleware(db)(mux))
}
