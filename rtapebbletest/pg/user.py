# vim: set expandtab ts=4 sw=4 filetype=python:

import logging
import textwrap

import psycopg2.extras

log = logging.getLogger(__name__)

class UserInserter(object):

    def __init__(self, email_address, display_name, password=None,user_status='started registration',
                 is_institution_superuser=False,did_acknowledge_eula=False,challenge_question='Answer the question',challenge_question_answer='Answer the question',date_password_changed=None):

        self.email_address = email_address
        self.display_name = display_name
        self.password = password
        self.is_institution_superuser = is_institution_superuser
        self.did_acknowledge_eula = did_acknowledge_eula
        self.challenge_question = challenge_question
        self.challenge_question_answer = challenge_question_answer
        self.date_password_changed = date_password_changed
        self.user_status=user_status

    @property
    def bound_variables(self):

        if self.password:

            return dict(
                email_address=self.email_address,
                display_name=self.display_name,
                password=self.password,
                person_status=self.user_status)

        else:

            return dict(
                email_address=self.email_address,
                display_name=self.display_name,
                person_status=self.user_status)

    @property
    def insert_query(self):

        if self.password:

            return textwrap.dedent("""
                insert into people
                (
                    email_address,
                    display_name,
                    salted_hashed_password,
                    person_status
                )
                values
                (
                    %(email_address)s,
                    %(display_name)s,
                    crypt(%(password)s, gen_salt('md5')),
                    %(person_status)s
                )
                returning person_id
                """)

        else:

            return textwrap.dedent("""
                insert into people
                (
                    email_address,
                    display_name,
                    person_status
                )
                values
                (
                    %(email_address)s,
                    %(display_name)s,
                    %(person_status)s
                )
                returning person_id
                """)

    def execute(self, dbconn):

        cursor = dbconn.cursor()

        cursor.execute(self.insert_query, self.bound_variables)

        return cursor.fetchone()


class LockOutPeople(object):

    def __init__(self, lockout_interval):
        self.lockout_interval = lockout_interval

    def lock_out_inactive(self, pgconn):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            update people
                set person_status = 'deactivated'
                where person_status <> 'deactivated' AND person_id in (
                    select person_id
                    from horsemeat_sessions
                    group by person_id
                    having current_timestamp - max(inserted) > interval %(interval)s
            )
            """), {
                'interval': self.lockout_interval

            })

        return cursor.rowcount

    def get_all_inactive_users(self, pgconn):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select hmpl.person_id, max(hmpl.inserted), p.display_name,p.email_address
                    from horsemeat_sessions hmpl
                    join people p on hmpl.person_id = p.person_id
                    group by hmpl.person_id, p.display_name, p.email_address
                    having current_timestamp - max(hmpl.inserted) > interval %(interval)s
            """), {
                'interval': self.lockout_interval

            })

        return cursor



class PasswordUpdater(object):

    """
    pu = PasswordUpdater('matt@plus1.com', 'abcde')
    pu.update_password(pgconn)
    """

    def __init__(self, email_address, new_password):
        self.email_address = email_address
        self.new_password = new_password

    @property
    def update_query(self):

        return textwrap.dedent("""
            update people

            set salted_hashed_password =
            crypt(%(new_password)s, gen_salt('md5')),
            person_status='confirmed'

            where email_address = (%(email_address)s)
            returning person_id
            """)

    @property
    def bound_variables(self):

        return dict(
            new_password=self.new_password,
            email_address=self.email_address)

    def execute(self, dbconn):

        cursor = dbconn.cursor()
        cursor.execute(self.update_query, self.bound_variables)

    # I love aliases.
    update_password = execute

def get_person_details(pgconn, person_id):

    cursor = pgconn.cursor()

    cursor.execute(textwrap.dedent("""
        select (p.*)::people as p
        from people p
        where person_id = (%(person_id)s)
        """), {'person_id': person_id})

    return cursor.fetchone().p

def verify_credentials(pgconn, person_id, email_address, password):

    cursor = pgconn.cursor()

    # Later, consider returning some registered composite type.
    cursor.execute(textwrap.dedent("""
        select exists(
            select *
            from people
            where person_id = %(person_id)s
            and email_address = %(email_address)s
            and salted_hashed_password = crypt(
                %(password)s,
                salted_hashed_password)
        )
        """), {
            'person_id': person_id,
            'email_address': email_address,
            'password': password
        })

    return cursor.fetchone().exists

class PersonFactory(psycopg2.extras.CompositeCaster):

    def make(self, values):
        d = dict(zip(self.attnames, values))
        return Person(**d)


class Person(object):

    def __init__(self, person_id, email_address, salted_hashed_password,
        person_status, display_name, is_superuser, is_institution_superuser, did_acknowledge_eula, challenge_question, challenge_question_answer, date_password_changed, inserted, updated):

        self.person_id = person_id
        self.email_address = email_address
        self.salted_hashed_password = salted_hashed_password
        self.person_status = person_status
        self.display_name = display_name
        self.is_superuser = is_superuser
        self.is_institution_superuser = is_institution_superuser
        self.did_acknowledge_eula = did_acknowledge_eula
        self.challenge_question = challenge_question
        self.challenge_question_answer = challenge_question_answer
        self.date_password_changed=date_password_changed
        self.inserted = inserted
        self.updated = updated

    def __repr__(self):
        return '<{0}.{1} ({2}:{3}) at 0x{4:x}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.person_id,
            self.display_name,
            id(self))

    def __eq__(self, other):
        return self.person_id == getattr(other, 'person_id', -1)

    @classmethod
    def by_email_address(cls, pgconn, email_address):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select (p.*)::people as p
            from people p
            where email_address = %(email_address)s
            """), {'email_address': email_address})

        if cursor.rowcount:
            return cursor.fetchone().p

        else:
            raise KeyError("Sorry, couldn't find {0}!".format(
                email_address))

    @classmethod
    def all_colleagues_everywhere(cls, pgconn, person_id):

        """
        Return all the people we can find at any institution (aka
        client) affiliated with this person_id.
        """

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select distinct (p.*)::people as p

            from people_clients_link pcl1

            join people_clients_link pcl2
            on pcl1.client_uuid = pcl2.client_uuid

            join people p
            on pcl2.person_id = p.person_id

            where pcl1.person_id = %(person_id)s
            """), {'person_id': person_id})

        return cursor

    def all_my_colleagues(self, pgconn):

        return self.all_colleagues_everywhere(pgconn, self.person_id)


    def all_my_internal_clients(self, pgconn):

        """
        Return all the clients where the person
        is in the 'internal' associated with this person.
        """
        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select c.client_uuid, c.display_name

            from clients c

            join people_clients_link pcl
            on pcl.client_uuid = c.client_uuid

            where person_id = %(person_id)s
        """), {'person_id': self.person_id})

        return cursor.fetchall()



    @property
    def __jsondata__(self):

        return {k:v for (k, v) in self.__dict__.items()
            if k in set([
                'display_name',
                'email_address',
                'person_id'])}

    @classmethod
    def all_binder_members(cls, pgconn, binder_id):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""

          select pcl2.person_id,
                 p.display_name,
                 (case when b.owner_id = pcl2.person_id
                  then 'primary coordinator'
                  else bul.user_link_type end) as user_link_type

          from people_clients_link pcl2

          join (select b.binder_id, pcl.client_uuid
              from binders b

              join people p
              on p.person_id = b.owner_id

              join people_clients_link pcl
              on pcl.person_id = p.person_id

              where  b.binder_id = %(binder_id)s) pcl3
          on pcl3.client_uuid = pcl2.client_uuid

          join people p on p.person_id = pcl2.person_id

          left join binder_user_link bul
          on bul.person_id = pcl2.person_id
          and pcl3.binder_id = bul.binder_id

          join binders b on pcl3.binder_id = b.binder_id

          """), {'binder_id': binder_id})

        return cursor

    @classmethod
    def by_person_id(cls, pgconn, person_id):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select (p.*)::people as p
            from people p
            where person_id = %(person_id)s
            """), {'person_id': person_id})

        if cursor.rowcount:
            return cursor.fetchone().p


def get_candidate_read_only_users(pgconn, person_id, binder_id):

    cursor = pgconn.cursor()

    cursor.execute(textwrap.dedent("""
        select distinct people.*

        from people

        join people_clients_link
        on people_clients_link.person_id = people.person_id

        where client_uuid in (
            select client_uuid
            from people_clients_link
            where person_id = %(person_id)s
        )
        and people_clients_link.person_id != %(person_id)s

        and people_clients_link.person_id not in (
            select person_id
            from binder_user_link
            where binder_id = %(binder_id)s
        )

        and people_clients_link.person_id not in (
        select owner_id
        from binders
        where binder_id = %(binder_id)s
    )

    and people.person_status = 'confirmed'

    order by people.display_name

    """), {'person_id': person_id, 'binder_id': binder_id})

    return cursor

def get_candidate_auditors(pgconn, binder_id, user_link_type):

    """
    Return a list of people that could be added as an auditor
    to the binder with binder_id.

    Exclude from the list:

    *   this binder's owner
    *   any read-only users on this binder
    *   anyone who is already an auditor on this binder

    """

    cursor = pgconn.cursor()

    cursor.execute(textwrap.dedent("""

        select distinct (p2.*)::people as p

        from binders b

        join people_clients_link pcl
        on b.owner_id = pcl.person_id

        join people_clients_link pcl2
        on pcl.client_uuid = pcl2.client_uuid

        join people p2
        on pcl2.person_id = p2.person_id

        where b.binder_id = (%(binder_id)s)

        -- skip the owner of the binder
        and p2.person_id != b.owner_id

        -- skip people with this status
        and p2.person_id not in (
            select person_id
            from binder_user_link
             where binder_id = (%(binder_id)s)
             and user_link_type = (%(user_link_type)s)
         )
        """), {'binder_id': binder_id, 'user_link_type':user_link_type})

    return cursor


class PasswordHistory(object):

    def __init__(self,pgconn,email_address=None,person_id=None):
        self.pgconn = pgconn
        self.person_id = person_id
        self.email_address= email_address

        if self.person_id is None:

            cursor = self.pgconn.cursor()
            cursor.execute(textwrap.dedent("""select person_id from people where email_address= %(email_address)s"""), {'email_address': self.email_address})

            result =cursor.fetchone()
            self.person_id =result.person_id

    def check_password_history(self, new_password,insert_history_record=False):

        cursor = self.pgconn.cursor()


        bound_vars = {
            'person_id': self.person_id,
            'password': new_password,
            }

        cursor.execute(textwrap.dedent("""select exists(select inserted from password_history where

                    (person_id= %(person_id)s) and
                    (salted_hashed_password = crypt(%(password)s,salted_hashed_password))
                    group by inserted
                    having current_timestamp - max(inserted) < interval '1 YEAR')"""), bound_vars)

        ret_val =False

        if cursor.rowcount > 0:
            result = cursor.fetchone()
            if result.exists==True:
                ret_val =True
                if insert_history_record==True:
                    self.insert_password_history(new_password)
        return ret_val

    def insert_password_history(self, new_password,salt_password=False):

            bound_vars = {
                'person_id': self.person_id,
                'password': new_password,
            }

            cursor =self.pgconn.cursor()

            if salt_password==True:
                cursor.execute(textwrap.dedent("""insert into password_history
                    (
                        person_id,
                        salted_hashed_password
                    )
                    values
                    (
                        %(person_id)s,
                        crypt(%(password)s, gen_salt('md5'))
                    )
                    returning person_id

                """), bound_vars)

            else:

                cursor.execute(textwrap.dedent("""insert into password_history
                    (
                        person_id,
                        salted_hashed_password
                    )
                    values
                    (
                        %(person_id)s,
                        %(password)s
                    )
                    returning person_id

                """), bound_vars)

            if cursor.rowcount >0:
                return cursor.fetchone()



