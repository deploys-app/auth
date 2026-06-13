package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// IntrospectHandler implements OAuth 2.0 Token Introspection (RFC 7662). The MCP
// resource server calls it to validate an opaque bearer token it received.
//
// The endpoint is itself protected by a shared secret (INTROSPECTION_TOKEN)
// presented as `Authorization: Bearer <token>`, so it is not a public oracle.
type IntrospectHandler struct {
	Token string
}

func (h IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Token == "" {
		http.Error(w, "introspection not configured", http.StatusServiceUnavailable)
		return
	}
	expected := "Bearer " + h.Token
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token := r.PostFormValue("token")
	if token == "" {
		writeInactive(w)
		return
	}

	ctx := r.Context()
	email, exp, err := lookupToken(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		writeInactive(w)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "introspect: lookup token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"active":     true,
		"sub":        email,
		"username":   email,
		"token_type": "Bearer",
		"exp":        exp,
	})
}

func writeInactive(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"active": false})
}
