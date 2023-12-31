create table sessions (
	id         text not null,
	data       json not null,
	created_at integer default current_timestamp,
	primary key (id)
);
create index sessions_created_at_idx on sessions (created_at);

create table oauth2_clients (
	id           text not null,
	secret       text not null,
	redirect_uri text not null,
	created_at   integer default current_timestamp,
	primary key (id)
);

create table oauth2_codes (
	id         text not null,
	client_id  text not null,
	email      text not null,
	created_at integer default current_timestamp,
	primary key (id),
	foreign key (client_id) references oauth2_clients (id) on delete cascade
);
create index oauth2_codes_created_at_idx on oauth2_codes (created_at);

create table tokens (
	id         text    not null,
	email      text    not null,
	client_id  text    not null,
	created_at integer default current_timestamp,
	expires_at integer not null,
	primary key (id),
	foreign key (client_id) references oauth2_clients (id) on delete cascade
);
create index tokens_expires_at_idx on tokens (expires_at);
