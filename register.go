package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// RegisterHandler implements OAuth 2.0 Dynamic Client Registration (RFC 7591).
// It only issues public clients (token_endpoint_auth_method "none"); they
// authenticate via PKCE, so no client secret is generated. This is the path MCP
// CLIs use to obtain a client_id without manual provisioning.
type RegisterHandler struct {
	BaseURL string
	// Limiter caps registrations per source IP. nil disables limiting (tests).
	Limiter *registerLimiter
}

func (h RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Limiter != nil && !h.Limiter.allow(clientIP(r)) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "too_many_requests",
			"error_description": "registration rate limit exceeded; retry later",
		})
		return
	}

	var req struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		registrationError(w, "invalid_client_metadata", "invalid request body")
		return
	}

	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		registrationError(w, "invalid_client_metadata", "only token_endpoint_auth_method \"none\" is supported")
		return
	}
	if len(req.RedirectURIs) == 0 {
		registrationError(w, "invalid_redirect_uri", "at least one redirect_uri is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if !validRegistrationRedirectURI(uri) {
			registrationError(w, "invalid_redirect_uri", "redirect_uri must be https or http loopback: "+uri)
			return
		}
	}

	ctx := r.Context()
	clientID := generateClientID()
	err := insertOAuth2Client(ctx, &OAuth2Client{
		ID:                      clientID,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: "none",
		ClientName:              req.ClientName,
	})
	if err != nil {
		slog.ErrorContext(ctx, "register: insert oauth2 client", "error", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server_error"})
		return
	}

	resp := map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func registrationError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
