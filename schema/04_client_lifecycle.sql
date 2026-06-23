-- Bound dynamically-registered (DCR) public clients so abandoned ones can be
-- reaped, without ever touching operator-seeded or confidential clients.

-- Mark which clients were created via Dynamic Client Registration (RFC 7591).
-- Only these are eligible for idle GC; everything else (dynamically_registered =
-- false: the Google web client, operator-seeded public clients) is never reaped.
alter table oauth2_clients add column if not exists dynamically_registered bool        not null default false;

-- last_used_at is stamped at each authorize so GC can reap by IDLE time, not by
-- creation age — an actively-reused client (the CLI reuses one client_id) never
-- expires. Null until first use; GC falls back to created_at for never-used rows.
alter table oauth2_clients add column if not exists last_used_at            timestamptz;

create index if not exists oauth2_clients_gc_idx
	on oauth2_clients (dynamically_registered, last_used_at);
