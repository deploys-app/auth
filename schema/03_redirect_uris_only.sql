-- Consolidate redirect-URI matching onto redirect_uris and drop the legacy
-- single-value redirect_uri column.
--
-- Backfill first so existing (confidential) clients keep working: a value
-- containing a glob '*' becomes a "regexp:" entry — the matcher applies the same
-- escape-dots / '*'->'.*' dialect the old column used, so behaviour is preserved
-- and patterns like console-pr-\d+-<id>.rcf2.deploys.app are honoured — while an
-- exact value is copied verbatim. Public / DCR clients already use redirect_uris
-- (their redirect_uri is '') and are skipped. The row backfill is idempotent.
update oauth2_clients
set redirect_uris = array_append(
		redirect_uris,
		case when position('*' in redirect_uri) > 0
			then 'regexp:' || redirect_uri
			else redirect_uri
		end
	)
where redirect_uri <> ''
	and not (redirect_uri = any(redirect_uris))
	and not (('regexp:' || redirect_uri) = any(redirect_uris));

alter table oauth2_clients drop column redirect_uri;
