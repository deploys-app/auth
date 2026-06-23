package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// registerLimiter is a small per-IP fixed-window limiter for the unauthenticated
// /register (Dynamic Client Registration) endpoint. DCR mints a permanent client
// row, so an unbounded /register is an abuse vector; this caps registrations per
// source IP per window. It is in-memory and per-instance — defense in depth, not
// a hard global guarantee — and is the burst control that complements the idle
// GC (which only bounds steady-state size).
type registerLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newRegisterLimiter(max int, window time.Duration) *registerLimiter {
	l := &registerLimiter{hits: map[string][]time.Time{}, max: max, window: window}
	go l.sweepLoop()
	return l
}

// allow records a hit for key and reports whether it is within the per-window
// cap. It also prunes the key's expired hits in place.
func (l *registerLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.max {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)
	return true
}

// sweepLoop periodically drops keys whose hits have all expired, so the map does
// not grow without bound across many distinct source IPs.
func (l *registerLimiter) sweepLoop() {
	for {
		time.Sleep(l.window)
		cutoff := time.Now().Add(-l.window)
		l.mu.Lock()
		for k, ts := range l.hits {
			alive := ts[:0]
			for _, t := range ts {
				if t.After(cutoff) {
					alive = append(alive, t)
				}
			}
			if len(alive) == 0 {
				delete(l.hits, k)
			} else {
				l.hits[k] = alive
			}
		}
		l.mu.Unlock()
	}
}

// clientIP extracts the caller's IP for rate-limiting. It uses the RIGHTMOST
// X-Forwarded-For entry — the hop appended by the trusted front proxy (parapet),
// i.e. the peer parapet actually saw — not the leftmost, which is client-supplied
// and therefore spoofable (an attacker could rotate it to evade the per-IP cap).
// Falls back to RemoteAddr when no XFF is present.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
