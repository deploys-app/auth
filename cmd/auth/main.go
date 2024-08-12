package main

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/acoshift/pgsql/pgctx"
	_ "github.com/lib/pq"

	"github.com/deploys-app/auth"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	oauth2ClientID := os.Getenv("OAUTH2_CLIENT_ID")
	if oauth2ClientID == "" {
		panic("missing OAUTH2_CLIENT_ID")
	}
	oauth2ClientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")

	sqlURL := os.Getenv("SQL_URL")
	if sqlURL == "" {
		panic("missing SQL_URL")
	}
	db, err := sql.Open("postgres", sqlURL)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.Handle("GET /", auth.RedirectHandler{OAuth2ClientID: oauth2ClientID})
	mux.Handle("GET /callback", auth.CallbackHandler{
		OAuth2ClientID:     oauth2ClientID,
		OAuth2ClientSecret: oauth2ClientSecret,
	})
	mux.Handle("GET /revoke", auth.RevokeHandler{}) // TODO: remove ?
	mux.Handle("POST /revoke", auth.RevokePostHandler{})
	mux.Handle("POST /token", auth.TokenHandler{})

	http.ListenAndServe(":"+port, pgctx.Middleware(db)(mux))
}
