-- Refresh tokens: long-lived, single-use (rotating) credentials issued to public
-- clients (CLI / MCP connector) alongside the short-lived access token, so they
-- can silently obtain a fresh access token without a full re-authorization.
--
-- Stored as a SHA-256 hash and bound to the issuing client. Kept in its own table
-- (not user_tokens) so a refresh token can never be presented as an API bearer:
-- the apiserver and /introspect resolve only user_tokens. The FK cascade reaps a
-- client's refresh tokens if the client itself is ever removed (idle DCR GC).
create table if not exists refresh_tokens (
	token      string,
	email      string      not null,
	client_id  string      not null,
	created_at timestamptz not null default now(),
	expires_at timestamptz not null,
	primary key (token),
	foreign key (client_id) references oauth2_clients (id) on delete cascade
);
create index if not exists refresh_tokens_expires_at_idx on refresh_tokens (expires_at);
