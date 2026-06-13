package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsURL(t *testing.T) {
	for in, want := range map[string]bool{
		"https://app.example.com/cb": true,
		"http://127.0.0.1:8080/cb":   true,
		"app.example.com":            false, // no scheme
		"ftp://example.com":          false, // unsupported scheme
		"https://":                   false, // no host
		"":                           false,
	} {
		if got := isURL(in); got != want {
			t.Errorf("isURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestExtractEmailFromIDToken(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		email, err := extractEmailFromIDToken(fakeIDToken("user@example.com"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if email != "user@example.com" {
			t.Errorf("email = %q, want user@example.com", email)
		}
	})
	t.Run("malformed (not 3 parts)", func(t *testing.T) {
		if _, err := extractEmailFromIDToken("only.two"); err == nil {
			t.Error("expected error for malformed token")
		}
	})
}

func TestHashToken(t *testing.T) {
	a := hashToken("deploys-api.abc")
	if a == "" {
		t.Fatal("hashToken returned empty")
	}
	if a != hashToken("deploys-api.abc") {
		t.Error("hashToken is not deterministic")
	}
	if a == hashToken("deploys-api.different") {
		t.Error("different inputs produced the same hash")
	}
}

func TestMetadataHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	MetadataHandler{BaseURL: "https://auth.test"}.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var meta struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		RegistrationEndpoint              string   `json:"registration_endpoint"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if meta.Issuer != "https://auth.test" {
		t.Errorf("issuer = %q", meta.Issuer)
	}
	if meta.AuthorizationEndpoint != "https://auth.test/" {
		t.Errorf("authorization_endpoint = %q", meta.AuthorizationEndpoint)
	}
	if meta.TokenEndpoint != "https://auth.test/token" {
		t.Errorf("token_endpoint = %q", meta.TokenEndpoint)
	}
	if meta.RegistrationEndpoint != "https://auth.test/register" {
		t.Errorf("registration_endpoint = %q", meta.RegistrationEndpoint)
	}
	if !contains(meta.CodeChallengeMethodsSupported, "S256") {
		t.Errorf("code_challenge_methods_supported = %v, want S256", meta.CodeChallengeMethodsSupported)
	}
	if !contains(meta.TokenEndpointAuthMethodsSupported, "none") ||
		!contains(meta.TokenEndpointAuthMethodsSupported, "client_secret_post") {
		t.Errorf("token_endpoint_auth_methods_supported = %v", meta.TokenEndpointAuthMethodsSupported)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
