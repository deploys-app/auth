-- Seed the well-known public client the deploys CLI bakes in, so ordinary CLI
-- logins never call /register (which would mint a permanent row per machine).
--
-- It is operator-seeded, so dynamically_registered keeps its default of false
-- and the GC never reaps it. The port-less loopback redirect matches any
-- 127.0.0.1:<port>/callback (the auth server ignores the port for loopback
-- hosts). Pure DML, kept in its own migration so it never shares an implicit
-- transaction with the column-adding DDL in 04. Idempotent.
insert into oauth2_clients (id, secret, redirect_uris, token_endpoint_auth_method, client_name)
values ('deploys-cli', null, array['http://127.0.0.1/callback'], 'none', 'deploys CLI')
on conflict (id) do nothing;
