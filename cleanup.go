package main

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// startCleanupWorker periodically removes expired oauth2 sessions and codes.
// Both have a 1-hour TTL but are only deleted on use, so abandoned rows would
// otherwise accumulate. Registered clients are never reaped — MCP clients reuse
// their client_id across logins.
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
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			slog.ErrorContext(ctx, "cleanup: delete expired rows", "error", err)
		}
	}
}
