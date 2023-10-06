create table sessions (
	id         text,
	data       json,
	created_at integer default current_timestamp,
	primary key (id)
);
