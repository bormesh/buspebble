create table person_statuses
(
    title citext primary key,
    description text,
    inserted timestamp not null default now(),
    updated timestamp
);

create trigger person_statuses_set_updated_column
before update
on person_statuses
for each row
execute procedure set_updated_column();

insert into person_statuses
(title)
values
('started registration'),
('needs to pick password'),
('confirmed'),
('deactivated'),
('canceled registration');

create domain email_address_type as citext check(value ~ E'^.+@.+\\..+');

create table people
(
    person_id serial primary key,
    email_address email_address_type not null unique,

    salted_hashed_password text,

    person_status citext not null default 'started registration'
    references person_statuses (title)
    on delete cascade
    on update cascade,

    display_name text,

    -- super users are different than just local project administrators.
    is_superuser boolean not null default false,

    inserted timestamp not null default now(),
    updated timestamp

);

create trigger people_set_updated_column
before update
on people
for each row
execute procedure set_updated_column();

-- The only thing that goes in the cookie should be the session ID and
-- the signature.  Everything else goes in here.  Deal with it.
create table webapp_sessions
(
    session_id serial primary key,
    expires timestamp not null default now() + interval '60 minutes',

    person_id integer
    references people (person_id)
    on delete cascade
    on update cascade,

    news_message text,
    redirect_to_url text,

    inserted timestamp not null default now(),
    updated timestamp
);

create trigger webapp_sessions_set_updated_column
before update
on webapp_sessions
for each row
execute procedure set_updated_column();

create table webapp_session_data
(
    session_id integer not null
    references webapp_sessions (session_id)
    on delete cascade
    on update cascade,

    -- namespace is a crappy name and when I figure out a better name,
    -- I'll rename this column.

    -- The point is to allow you to separate data into separate
    -- categories.

    -- For example, each HTML form could store the user's submitted data
    -- (for redrawing later) in a separate namespace.

    namespace text not null,

    primary key (session_id, namespace),
    session_data hstore,
    inserted timestamp not null default now(),
    updated timestamp
);

create trigger webapp_session_data_set_updated_column
before update
on webapp_session_data
for each row
execute procedure set_updated_column();

create table message_types
(
    title citext primary key,
    description text,
    inserted timestamp not null default now(),
    updated timestamp
);

create trigger message_types_set_updated_column
before update
on message_types
for each row
execute procedure set_updated_column();

insert into message_types
(title)
values
('registration'),
('forgot password')
;


-- Put rows in here to send emails.
create table email_message_queue
(
    email_message_queue_id serial primary key,
    nonce uuid not null default uuid_generate_v4(),

    -- the redeemed columns tracks if this message has already been
    -- redeemed.  if "redeemed" sounds goofy, think of it as when the
    -- user used this message to do something.
    redeemed timestamp,

    recipient_email_address email_address_type
    not null references people (email_address)
    on delete cascade
    on update cascade,

    message_type citext not null references message_types (title)
    on delete cascade
    on update cascade,

    selected_for_delivery timestamp,

    -- Right now, python passes in these values.  I bet there's some
    -- cool way to grab these out of some environmental variables.
    selector_pid int,
    selector_host text,

    sent timestamp,

    inserted timestamp not null default now(),
    updated timestamp
);

-- I just learned about this "comment" feature.
-- After you set these comments, then when you do \d
-- email_message_queue, this text is now part of the table definition.
-- It seems like a good way to help explain stuff.
comment on column email_message_queue.sent is
E'A NULL value means that the message has not been sent yet, while a
timestamp value shows the moment when it was sent.';

comment on column email_message_queue.selected_for_delivery is
E'A NULL value means no script is processing this row.  A timestamp
is the date when the script began processing this row.  Also look at
selector_pid and selector_host for more information';

create trigger email_message_queue_set_updated_column
before update
on email_message_queue
for each row
execute procedure set_updated_column();
