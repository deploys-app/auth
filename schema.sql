create table sessions (
	id         text not null,
	data       json not null,
	created_at integer default current_timestamp,
	primary key (id)
);

create table oauth2_clients (
	id           text not null,
	secret       text not null,
	redirect_uri text not null,
	created_at   integer default current_timestamp,
	primary key (id)
);

create table oauth2_codes (
	id         text not null,
	email      text not null,
	created_at integer default current_timestamp,
	primary key (id)
);
