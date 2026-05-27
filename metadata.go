package main

import (
	"encoding/json"
	"net/http"
)

// MetadataHandler serves OAuth 2.0 Authorization Server Metadata (RFC 8414).
// MCP clients fetch this to discover the authorize, token and registration
// endpoints plus the supported PKCE methods and client auth methods.
type MetadataHandler struct {
	BaseURL string
}

func (h MetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	meta := map[string]any{
		"issuer":                                h.BaseURL,
		"authorization_endpoint":                h.BaseURL + "/",
		"token_endpoint":                        h.BaseURL + "/token",
		"registration_endpoint":                 h.BaseURL + "/register",
		"revocation_endpoint":                   h.BaseURL + "/revoke",
		"introspection_endpoint":                h.BaseURL + "/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(meta)
}
