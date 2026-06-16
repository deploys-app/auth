package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"regexp"
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

// redirectRegexpPrefix marks a redirect_uris entry as a pattern rather than an
// exact URI. Such entries are operator-provisioned only — DCR rejects them (see
// validRegistrationRedirectURI) — so a self-registered client can never widen
// its own redirect matching.
const redirectRegexpPrefix = "regexp:"

// redirectURIAllowed reports whether got matches one of the client's registered
// redirect URIs. An entry is matched exactly (scheme + host + path; the port may
// vary for loopback per RFC 8252) unless it carries the "regexp:" prefix, in
// which case the remainder is a pattern (see matchRedirectPattern).
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
		if pattern, ok := strings.CutPrefix(raw, redirectRegexpPrefix); ok {
			if matchRedirectPattern(pattern, got) {
				return true
			}
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

// matchRedirectPattern matches got against an operator-provisioned redirect
// pattern using the deploys glob dialect: literal '.' and '/' are escaped, '*'
// expands to '.*', and any other regex metacharacters (e.g. \d+) are honoured.
// The pattern is anchored ^...$ against the whole redirect URI, so it cannot
// match a broader host than written. A malformed pattern denies (never panics);
// Go's RE2 engine guarantees linear-time matching (no ReDoS).
//
// Matching is case-sensitive (unlike the host-only EqualFold of the exact path),
// so write the host in lowercase — the authority of an inbound redirect URI is
// already lowercase (browsers normalise it; generated preview hosts are
// lowercase). Being case-sensitive only ever denies, never widens.
func matchRedirectPattern(pattern, got string) bool {
	p := strings.ReplaceAll(pattern, ".", `\.`)
	p = strings.ReplaceAll(p, "/", `\/`)
	p = strings.ReplaceAll(p, "*", `.*`)
	re, err := regexp.Compile(`^` + p + `$`)
	if err != nil {
		return false
	}
	return re.MatchString(got)
}

// validRegistrationRedirectURI enforces the redirect URIs a client may register:
// HTTPS anywhere, or plain HTTP only for loopback (native/CLI clients).
func validRegistrationRedirectURI(s string) bool {
	// "regexp:" patterns are operator-provisioned only: a dynamically registered
	// (DCR) client may register exact URIs but never a pattern, which could match
	// hosts it does not control.
	if strings.HasPrefix(s, redirectRegexpPrefix) {
		return false
	}
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
