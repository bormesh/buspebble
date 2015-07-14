create table routes
(
    route_id serial primary key,

    rta_internal_route_id integer not null,

    title citext,
    description text,
    inserted timestamp not null default now(),
    updated timestamp
);

create trigger routes_set_updated_column
before update
on routes
for each row
execute procedure set_updated_column();

insert into routes
(title, rta_internal_route_id)
values
('32 Cedar Road', 149),
('7 Euclid Heights', 103);


create table destinations
(
    destination citext primary key,

    inserted timestamp not null default now(),
    updated timestamp
);

create trigger destinations_set_updated_column
before update
on destinations
for each row
execute procedure set_updated_column();

insert into destinations
(destination)
values
('Richmond'),
('Montefiore'),
('East 89th-Euclid');

create table stops
(

    stop_id serial primary key,

    rta_internal_stop_id integer not null,

    title citext,

    route_id integer not null references routes(route_id),

    destination citext not null references
    destinations (destination),

    inserted timestamp not null default now(),
    updated timestamp

);

create trigger stops_set_updated_column
before update
on stops
for each row
execute procedure set_updated_column();

insert into stops
(rta_internal_stop_id, title, destination, route_id)
values
(9411, 'EUCLID HTS BLVD & DERBYSHIRE RD', 'East 89th-Euclid', (select route_id from routes where rta_internal_route_id = 103)),
(9405, 'EUCLID HTS BLVD & LENNOX RD', 'Richmond', (select route_id from routes where rta_internal_route_id = 103));


create table scheduled_stops
(
    stop_id integer references stops (stop_id),

    scheduled_stop_time timetz not null,

    primary key (stop_id, scheduled_stop_time),

    inserted timestamp not null default now(),
    updated timestamp
);

create trigger scheduled_stops_set_updated_column
before update
on scheduled_stops
for each row
execute procedure set_updated_column();

insert into scheduled_stops
(scheduled_stop_time, stop_id)
values
( '13:04:00', (select stop_id from stops where rta_internal_stop_id = 9411) ),
( '13:49:00', (select stop_id from stops where rta_internal_stop_id = 9411) ),
( '02:34:00', (select stop_id from stops where rta_internal_stop_id = 9411) ),
( '03:01:00', (select stop_id from stops where rta_internal_stop_id = 9405) ),
( '03:46:00', (select stop_id from stops where rta_internal_stop_id = 9405) ),
( '04:26:00', (select stop_id from stops where rta_internal_stop_id = 9405) );


create table predicted_stop_times
(
    predicted_stop_id serial primary key,

    stop_id integer not null,

    scheduled_stop_time timetz not null,

    foreign key (stop_id, scheduled_stop_time)
    references scheduled_stops (stop_id, scheduled_stop_time),

    predicted_stop_time timetz not null,

    inserted timestamp not null default now(),
    updated timestamp
);

create trigger predicted_stop_times_set_updated_column
before update
on predicted_stop_times
for each row
execute procedure set_updated_column();


