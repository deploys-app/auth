-- MCP / OAuth 2.1 support (public clients, PKCE, DCR, resource indicators).

alter table oauth2_clients alter column secret drop not null;
alter table oauth2_clients alter column redirect_uri set default '';
alter table oauth2_clients add column if not exists redirect_uris              string[] not null default array[]::string[];
alter table oauth2_clients add column if not exists token_endpoint_auth_method string not null default 'client_secret_post';
alter table oauth2_clients add column if not exists client_name                string not null default '';

alter table oauth2_codes add column if not exists code_challenge        string not null default '';
alter table oauth2_codes add column if not exists code_challenge_method string not null default '';
alter table oauth2_codes add column if not exists redirect_uri          string not null default '';
alter table oauth2_codes add column if not exists resource              string not null default '';

alter table oauth2_sessions add column if not exists code_challenge        string not null default '';
alter table oauth2_sessions add column if not exists code_challenge_method string not null default '';
alter table oauth2_sessions add column if not exists resource              string not null default '';
