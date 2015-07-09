insert into people
(
    email_address,
    display_name,
    salted_hashed_password,
    person_status,
    is_superuser
)
values

(
    'matt@tplus1.com',
    'Matt Wilson',
    crypt('abc123', gen_salt('md5')),
    'confirmed',
    false
),

(
    'rob@216software.com',
    'Rob Heinen',
    crypt('abc123', gen_salt('md5')),
    'confirmed',
    false
),

(
    'leroy@216software.com',
    'Leroy Jenkins',
    crypt('abc123', gen_salt('md5')),
    'confirmed',
    false
)
;
