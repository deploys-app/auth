package main

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// clientIdleTTL is how long a dynamically-registered (DCR) public client may go
// unused before it is reaped. Idle, not age: an actively-reused client (the
// CLI/MCP reuse one client_id) is touched at every authorize and so never
// expires. Generous, so a client idle between releases survives.
const clientIdleTTL = 90 * 24 * time.Hour

// startCleanupWorker periodically removes expired oauth2 sessions and codes, and
// reaps abandoned dynamically-registered clients. Sessions and codes have a
// 1-hour TTL but are only deleted on use, so abandoned rows would otherwise
// accumulate. DCR clients are reaped only when idle past clientIdleTTL; reused
// clients (touched at authorize) and all non-DCR clients — the Google web
// client, operator-seeded public clients like deploys-cli — are never reaped.
func startCleanupWorker(db *sql.DB) {
	go func() {
		for {
			cleanupExpired(db)
			time.Sleep(15 * time.Minute)
		}
	}()
}

func cleanupExpired(db *sql.DB) {
	ctx := context.Background()
	for _, q := range []string{
		`delete from oauth2_sessions where created_at < now() - interval '1 hour'`,
		`delete from oauth2_codes where created_at < now() - interval '1 hour'`,
		`delete from refresh_tokens where expires_at < now()`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			slog.ErrorContext(ctx, "cleanup: delete expired rows", "error", err)
		}
	}

	// Reap DCR clients idle past the TTL. coalesce(last_used_at, created_at) ages
	// a registered-but-never-used row from its creation. dynamically_registered =
	// false rows (Google web, operator-seeded) are never matched.
	cutoff := time.Now().Add(-clientIdleTTL)
	if _, err := db.ExecContext(ctx, `
		delete from oauth2_clients
		where dynamically_registered = true
		  and coalesce(last_used_at, created_at) < $1
	`, cutoff); err != nil {
		slog.ErrorContext(ctx, "cleanup: delete idle clients", "error", err)
	}
}
