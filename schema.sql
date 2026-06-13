create table oauth2_clients (
	id                         string,
	secret                     string,
	redirect_uri               string      not null default '',
	redirect_uris              string[]    not null default array[]::string[],
	token_endpoint_auth_method string      not null default 'client_secret_post',
	client_name                string      not null default '',
	created_at                 timestamptz not null default now(),
	primary key (id)
);

create table oauth2_codes (
	id                    string,
	client_id             string      not null,
	email                 string      not null,
	code_challenge        string      not null default '',
	code_challenge_method string      not null default '',
	redirect_uri          string      not null default '',
	resource              string      not null default '',
	created_at            timestamptz not null default now(),
	primary key (id),
	foreign key (client_id) references oauth2_clients (id) on delete cascade
);
create index oauth2_codes_created_at_idx on oauth2_codes (created_at);

create table oauth2_sessions (
	id                    string,
	client_id             string      not null,
	state                 string      not null,
	callback_state        string      not null,
	callback_url          string      not null,
	code_challenge        string      not null default '',
	code_challenge_method string      not null default '',
	resource              string      not null default '',
	created_at            timestamptz not null default now(),
	primary key (id)
);
create index oauth2_sessions_created_at_idx on oauth2_sessions (created_at);
