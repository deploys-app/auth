package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strings"
)

// verifyPKCE checks a PKCE code_verifier against the stored code_challenge.
// Only the S256 method is supported (OAuth 2.1 / MCP requirement).
func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// redirectURIAllowed reports whether got matches one of the registered exact
// redirect URIs. Per RFC 8252 the port is ignored for loopback addresses, so a
// CLI listening on an ephemeral localhost port is accepted.
func redirectURIAllowed(registered []string, got string) bool {
	gu, err := url.Parse(got)
	if err != nil {
		return false
	}
	for _, raw := range registered {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ru, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if ru.Scheme != gu.Scheme {
			continue
		}
		if !strings.EqualFold(ru.Hostname(), gu.Hostname()) {
			continue
		}
		if ru.Path != gu.Path {
			continue
		}
		if isLoopbackHost(gu.Hostname()) {
			return true
		}
		if ru.Port() == gu.Port() {
			return true
		}
	}
	return false
}

// validRegistrationRedirectURI enforces the redirect URIs a client may register:
// HTTPS anywhere, or plain HTTP only for loopback (native/CLI clients).
func validRegistrationRedirectURI(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackHost(u.Hostname())
	default:
		return false
	}
}
