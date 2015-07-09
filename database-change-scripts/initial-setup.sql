create table change_scripts
(
    script_path citext primary key,
    script_contents text,
    inserted timestamp not null default now(),
    updated timestamp
);

create or replace function set_updated_column ()
returns trigger
as
$$

begin

    NEW.updated = now();
    return NEW;

end;
$$
language plpgsql;

create trigger change_scripts_set_updated_column
before update
on change_scripts
for each row
execute procedure set_updated_column();
