package main

import "testing"

func TestVerifyPKCE(t *testing.T) {
	verifier, challenge := pkcePair()

	cases := []struct {
		name     string
		verifier string
		chal     string
		method   string
		want     bool
	}{
		{"valid S256", verifier, challenge, "S256", true},
		{"wrong verifier", "not-the-verifier", challenge, "S256", false},
		{"empty verifier", "", challenge, "S256", false},
		{"empty challenge", verifier, "", "S256", false},
		{"plain method rejected", verifier, verifier, "plain", false},
		{"empty method rejected", verifier, challenge, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := verifyPKCE(c.verifier, c.chal, c.method); got != c.want {
				t.Errorf("verifyPKCE(%q,%q,%q) = %v, want %v", c.verifier, c.chal, c.method, got, c.want)
			}
		})
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"localhost": true,
		"example.com": false,
		"10.0.0.1":  false,
		"":          false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestRedirectURIAllowed(t *testing.T) {
	cases := []struct {
		name       string
		registered []string
		got        string
		want       bool
	}{
		{"exact https", []string{"https://app.example.com/cb"}, "https://app.example.com/cb", true},
		{"loopback ignores port", []string{"http://127.0.0.1:1234/callback"}, "http://127.0.0.1:55001/callback", true},
		{"localhost ignores port", []string{"http://localhost:1/callback"}, "http://localhost:9999/callback", true},
		{"loopback path mismatch", []string{"http://127.0.0.1:1234/callback"}, "http://127.0.0.1:55001/other", false},
		{"https port mismatch", []string{"https://app.example.com:443/cb"}, "https://app.example.com:8443/cb", false},
		{"scheme mismatch", []string{"https://app.example.com/cb"}, "http://app.example.com/cb", false},
		{"host mismatch", []string{"https://app.example.com/cb"}, "https://evil.example.com/cb", false},
		{"not in list", []string{"https://a.example.com/cb"}, "https://b.example.com/cb", false},
		{"matches second entry", []string{"https://a.example.com/cb", "http://127.0.0.1:1/cb"}, "http://127.0.0.1:42/cb", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redirectURIAllowed(c.registered, c.got); got != c.want {
				t.Errorf("redirectURIAllowed(%v, %q) = %v, want %v", c.registered, c.got, got, c.want)
			}
		})
	}
}

func TestValidRegistrationRedirectURI(t *testing.T) {
	for uri, want := range map[string]bool{
		"https://app.example.com/cb":   true,
		"http://127.0.0.1:1234/cb":     true,
		"http://localhost/cb":          true,
		"http://app.example.com/cb":    false, // plain http only allowed for loopback
		"ftp://example.com":            false,
		"not-a-url":                    false,
		"":                             false,
	} {
		if got := validRegistrationRedirectURI(uri); got != want {
			t.Errorf("validRegistrationRedirectURI(%q) = %v, want %v", uri, got, want)
		}
	}
}
