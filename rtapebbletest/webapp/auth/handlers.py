# vim: set expandtab ts=4 sw=4 filetype=python:

import json
import logging
import random
import re
import string
import textwrap
import uuid
import datetime

import psycopg2
from rtapebbletest.webapp.framework.handler import Handler
from rtapebbletest.webapp.framework.response import Response
from rtapebbletest.model import message, session, user
from rtapebbletest.model.user import PasswordHistory as password_history

from rtapebbletest.model import numberoffailedloginattemps as loginattempt
from rtapebbletest.webapp.auth import scrubbers


log = logging.getLogger(__name__)

module_template_prefix = 'auth'
module_template_package = 'rtapebbletest.webapp.auth.authtemplates'

"""

How registration works:

1.  You register by doing a POST to /register with an email address and
    password. the system creates your account with a status "started
    registration".  The system sends you an email with a nonce.

2.  You POST your email and that nonce back to /confirm-email, and your
    account marked as verified.  Also, the system logs you in.

How logging in works:

1.  You POST an email and a password.  The system creates a row in the
    session table with your email address.

How logging out works:

1.  You POST to /logout, and the system marks your session as expired.

How resetting a password works:

1.  POST /send-password-reset-email with an email address.  The system
    will send a password-reset email with a nonce to the posted email
    address.

2.  POST /reset-password with the email address, the nonce, and the new
    password.

"""

class RegisterForm(Handler):

    """
    Draw a registration form.

    ::

        GET /register
    """


    """

    We want to turn this off for now

    """

    def route(self, req):

        return

        if req.is_GET and req.PATH_INFO == '/register':
            return self.handle

    def handle(self, req):

        tmpl = self.jinja2_environment.get_template('auth/register.html')
        return Response.template(tmpl)


class RegisterNewUser(Handler):

    """

    Matching request::

        POST /register

        email_address=matt@tplus1.com&password1=abc123&password2=abc123

    Do this:

        *   insert a user in the people table
        *   insert a confirm-registration email into the email queue
        *   redirect to /check-your-email
    """

    def route(self, req):

        if req.line_one == 'POST /register':
            return self.handle

    def handle(self, req):

        errors, values = self.scrub(req)

        if errors:

            tmpl = self.jinja2_environment.get_template('auth/register.html')
            return Response.template(tmpl, errors=errors, values=values)

        else:

            try:

                i = user.UserInserter(
                    values['email_address'],
                    values['display_name'],
                    values['password'])

                result = i.execute(self.pgconn)

            except psycopg2.IntegrityError, ex:

                log.exception(ex)
                log.error(ex.args)

                errors['general'] = ('Sorry, something went wrong when '
                    'I tried inserting this email address into the '
                    'database!')

                tmpl = self.jinja2_environment.get_template('auth/register.html')
                return Response.template(tmpl, errors=errors, values=values)

            # Remember, this else applies when no exceptions are raised.
            else:

                # Insert an email into the email queue.
                email_message = message.EmailMessageInserter(
                    values['email_address'],
                    'registration').execute(self.pgconn)

                # Now, immediately process that email.
                es = message.EmailSender(
                    self.cw,
                    email_message)

                es.send_email()

                resp = Response.redirect(
                    '{web_host}/check-your-email'.format(
                        web_host=self.cw.web_host))

                return resp

    def scrub(self, req):

        """
        Verify we got:

        *   email_address
        *   display_name
        *   password1
        *   password2

        And password1 and password2 must match each other.

        """

        errors, values = dict(), dict()

        if 'email_address' not in req.parsed_body:
            errors['email_address'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:

            email_address = req.parsed_body['email_address'][0]
            values['email_address'] = email_address

            # Make sure the submitted value looks like an email address.
            matches = re.match(r'.+@.+\..+', email_address)

            if not matches:
                errors['email_address'] = ("Sorry, this doesn't look "
                    "like a good email address")

            if not errors:

                # Now check if this email_address is already in the
                # database.  If it is, report that it is an exception.

                cursor = self.pgconn.cursor()

                cursor.execute(textwrap.dedent("""
                    select email_address
                    from people
                    where email_address = (%s)
                    """), [email_address])

                result = cursor.fetchone()

                if result:

                    errors['email_address'] = ('Sorry, this email address '
                        'is already in the database')

                    errors['general'] = 'Pick a new email!'

        # Check for display_name.
        if 'display_name' not in req.parsed_body:
            errors['display_name'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:
            values['display_name'] = req.parsed_body['display_name'][0]

        # Check for password 1.

        if 'password1' not in req.parsed_body:
            errors['password1'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:
            values['password1'] = req.parsed_body['password1'][0]

        # Check for password 2.

        if 'password2' not in req.parsed_body:
            errors['password2'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:
            values['password2'] = req.parsed_body['password2'][0]

        # Now verify password 1 and password 2 are the same.

        if ('password1' in values
            and 'password2' in values
            and values['password1'] != values['password2']):

            errors['password2'] = "This doesn't match the first password!"
            errors['general'] = "Passwords do not match!"

        elif ('password1' in values
            and 'password2' in values
            and values['password1'] == values['password2']):

            values['password'] = values['password1']

        return errors, values

class CheckYourEmailPage(Handler):

    def route(self, req):
        if req.line_one == 'GET /check-your-email':
            return self.handle

    def handle(self, req):

        tmpl = self.jinja2_environment.get_template('auth/check-your-email.html')
        return Response.template(tmpl)


class ConfirmEmailForm(Handler):

    """
    Draw a form that lets somebody punch in the nonce we email.

    Matching requests::

        GET /confirm-email
        GET /confirm-email?email_address=matt@tplus1.com
        GET /confirm-email?email_address=matt@tplus1.com&nonce=4416441a-d19f-437f-b610-0fbb0cc7dfed

    """

    def route(self, req):

        if req.is_GET and req.PATH_INFO == '/confirm-email':
            return self.handle

    def handle(self, req):

        errors, values = self.scrub(req)

        tmpl = self.jinja2_environment.get_template('auth/confirm-email.html')
        return Response.template(tmpl, errors=errors, values=values)

    def scrub(self, req):

        errors, values = dict(), dict()

        # Check for email
        if 'email_address' in req.parsed_QS:
            values['email_address'] = req.parsed_QS['email_address'][0]

        # Check for nonce
        if 'nonce' in req.parsed_QS:
            raw_nonce = req.parsed_QS['nonce'][0]

            try:
                values['nonce'] = uuid.UUID(raw_nonce)

            except ValueError as ex:
                log.exception(ex)
                errors['nonce'] = "This doesn't look right"
                values['nonce'] = raw_nonce

        return errors, values


class ConfirmEmail(Handler):

    """
    Verify the nonce, create a session, and then redirect somewhere.

    Requests should look like::

        POST /confirm-email

        email_address=matt@tplus1.com&nonce=4416441a-d19f-437f-b610-0fbb0cc7dfed

    """

    def route(self, req):

        if req.line_one == 'POST /confirm-email':
            return self.handle


    def handle(self, req):

        """
        Check for this email address and nonce.

        If it matches, update the user's status to 'needs to pick password'.

        Otherwise, redraw the form with error messages.
        """

        errors, values = self.scrub(req)

        if errors:

            tmpl = self.jinja2_environment.get_template('auth/confirm-email.html')
            return Response.template(tmpl, errors=errors, values=values)

        else:

            cursor = self.pgconn.cursor()

            cursor.execute(textwrap.dedent("""
                update people
                set person_status='needs to pick password',
                  challenge_question=(%(challenge_question)s),
                  challenge_question_answer=(%(challenge_question_answer)s)

                where email_address in (
                    select emq.recipient_email_address
                    from email_message_queue emq
                    join people p
                    on emq.recipient_email_address = p.email_address
                    where emq.nonce = %(nonce)s
                    and emq.recipient_email_address = %(email_address)s
                    and emq.sent is not null
                    and emq.message_type = 'registration'
                    and emq.redeemed is null
                    and p.person_status = 'started registration'
                )
                returning person_id
                """), values)

            if not cursor.rowcount:

                errors['general'] = "I couldn't find that email address and nonce"

                tmpl = self.jinja2_environment.get_template('auth/confirm-email.html')
                return Response.template(tmpl, errors=errors, values=values)

            # End of the gauntlet for confirming email address.
            person_id = cursor.fetchone().person_id

            si = session.SessionInserter(person_id)
            session_id = si.execute(self.pgconn)[0]


            resp = Response.relative_redirect('/')
            #tmpl = self.jinja2_environment.get_template('esignatures/esign_eula_form.html')
            #return Response.template(tmpl, errors=errors, values=values)

            resp.set_session_cookie(session_id, self.config_wrapper.app_secret)

            resp.set_news_message_cookie('You are confirmed!')

            return resp

    def scrub(self, req):

        errors, values = dict(), dict()

        # Check email address

        if 'email_address' in req.parsed_body:
            values['email_address'] = req.parsed_body['email_address'][0]



            is_a_match = re.match(r'.+@.+\..+', values['email_address'])

            if not is_a_match:
                errors['email_address'] = 'This does not look like a valid email address'

        else:
            errors['email_address'] = 'This is a required field!'


        if 'challenge_question' in req.parsed_body:
             values['challenge_question'] = req.parsed_body['challenge_question'][0]
        else:
            errors['challenge_question'] = 'This is a required field!'

        if 'challenge_question_answer' in req.parsed_body:
             values['challenge_question_answer'] = req.parsed_body['challenge_question_answer'][0]
        else:
            errors['challenge_question_answer'] = 'This is a required field!'

        # Check nonce

        if 'nonce' in req.parsed_body:

            raw_nonce = req.parsed_body['nonce'][0]

            try:

                values['nonce'] = uuid.UUID(raw_nonce)

            except ValueError as ex:
                log.exception(ex)
                errors['nonce'] = "This doesn't look right"
                values['nonce'] = raw_nonce

        else:
            errors['nonce'] = 'This is a required field!'

        return errors, values


class MyAccount(Handler):


    def route(self, req):

        if req.line_one in ('GET /my-account', 'GET /me') \
        and req.user:

            return self.handle

        elif req.line_one in ('GET /my-account', 'GET /me'):

            return self.prompt_for_login


    def handle(self, req):

        if '90days' in req.parsed_QS:
            ninety_days = req.parsed_QS['90days'][0]
            if ninety_days:
                return Response.tmpl('auth/me.html', ninety_days=True)

        return Response.tmpl('auth/me.html',ninety_days=False)


class LoginLogoutForm(Handler):

    """
    GET /login
    """

    def route(self, req):

        if req.line_one in ('GET /login', 'GET /logout'):
            return self.handle

    def handle(self, req):

        # If somebody is already logged in, draw the logout screen.
        if req.user:

            return Response.tmpl('auth/already-logged-in.html')

        # Otherwise, draw the login screen.
        else:

            return Response.tmpl('auth/login.html')


class Authenticator(Handler):

    """
    Check the submitted email address and password vs the database.
    """

    route_strings = set(['POST /login'])

    route = Handler.check_route_strings

    def handle(self, req):

        """
        Somebody might be trying to guess a valid (email address,
        password) combination, so the error messages I reply with are
        purposefully vague.
        """

        errors, values = self.scrub(req)


        # Check that we got all required data.

        if errors:

            cursor = self.pgconn.cursor()

            cursor.execute(textwrap.dedent("""
            select person_id,person_status
            from people p
            where email_address = %(email_address)s
            and (person_status = 'confirmed' or person_status='needs to sign eula' or person_status='locked out')

            """), values)

            result = cursor.fetchone()

            if result:
                person_id = result.person_id
                person_status = result.person_status

                if person_status == 'locked out':
                    errors['general'] = "This account has been locked due to too many attempts. Please contact your admininstrator. "
                else:

                    try:
                        la = loginattempt.FailedLoginAttempt()
                        la.insert_failed_attempt(self.pgconn,person_id)

                        num_of_failed_login = la.get_number_of_attempts(self.pgconn,person_id)

                        log.debug('number of failed attempts {0} for {1}.'.format(num_of_failed_login,person_id))

                        errors['numberofattemptedlogins'] = str(num_of_failed_login.number_of_attempts)

                        if num_of_failed_login.number_of_attempts == 4:
                            errors['general'] = "You have failed to login 4 times. The next unsuccesfully attempt will lock you out."


                        if num_of_failed_login.number_of_attempts >= 5:
                            errors['general'] = "This account has been locked due to too many attempts. Please contact your admininstrator. "

                            num_of_failed_login.lock_out_user(self.pgconn,person_id, self.cw, req.client_IP_address)

                        else:
                            errors['general'] = "This email and password is incorrect."
                    except Exception as ex:

                        log.exception(ex)
                        return self.not_found(req)
            else:
                errors['general'] = "This email and password is incorrect."

            tmpl = self.jinja2_environment.get_template('auth/login.html')
            return Response.template(tmpl, errors=errors, values=values)

        # Check if that email address is in the user table.  Don't say
        # that the email address is missing though; that would make it
        # easy for somebody to guess valid email addresses.



        cursor = self.pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select person_id, is_superuser,date_password_changed, person_status
            from people p
            where email_address = %(email_address)s

            and salted_hashed_password = crypt(
                %(password)s,
                salted_hashed_password)

            and (person_status = 'confirmed' or person_status='needs to sign eula' or person_status='locked out')

            """), values)

        result = cursor.fetchone()

        if not result:

            cursor.execute(textwrap.dedent("""
            select person_id
            from people p
            where email_address = %(email_address)s
            and (person_status = 'confirmed' or person_status='needs to sign eula' or person_status='locked out')

            """), values)

            result = cursor.fetchone()

            if result:
                person_id = result[0]
                try:
                    la = loginattempt.FailedLoginAttempt()
                    la.insert_failed_attempt(self.pgconn,person_id)

                    num_of_failed_login = la.get_number_of_attempts(self.pgconn,person_id)

                    errors['numberofattemptedlogins'] = str(num_of_failed_login.number_of_attempts)

                    if num_of_failed_login.number_of_attempts == 4:
                        errors['general'] = "You have failed to login 4 times. The next unsuccesfully attempt will lock you out."


                    if num_of_failed_login.number_of_attempts >= 5:
                        errors['general'] = "This account has been locked due to too many attempts. Please contact your admininstrator. "

                        num_of_failed_login.lock_out_user(self.pgconn,person_id, self.cw, req.client_IP_address)
                    else:
                        errors['general'] = "This email and password is incorrect."
                except Exception as ex:

                    log.exception(ex)
                    return self.not_found(req)
            else:
                errors['general'] = "This email and password is incorrect."


            tmpl = self.jinja2_environment.get_template('auth/login.html')
            return Response.template(tmpl, errors=errors, values=values)

        # This clause applies when the email and password matched the
        # database.
        else:

            person_id, is_superuser, date_password_changed, person_status = result

            if person_status == 'locked out':
                errors['general'] = "This account has been locked due to too many attempts. Please contact your admininstrator. "
                tmpl = self.jinja2_environment.get_template('auth/login.html')
                return Response.template(tmpl, errors=errors, values=values)
            else:
                cursor = self.cw.get_pgconn().cursor()

                cursor.execute(textwrap.dedent("""
                    update horsemeat_sessions
                    set expires = current_timestamp
                    where person_id = %(person_id)s
                    and expires > current_timestamp
                    returning session_id
                    """), {'person_id': person_id})

                session_IDs_killed = cursor.fetchall()

                if session_IDs_killed:

                    log.debug(
                        'I just killed {0} sessions for person_id {1}.'.format(
                            len(session_IDs_killed), person_id))

                    for killed_session_id in session_IDs_killed:

                        cursor.execute(textwrap.dedent("""
                            insert into user_activity_logs
                            (person_id, session_id, client_ip_address, action, extra_notes)
                            values
                            (%(person_id)s, %(session_id)s, %(client_ip_address)s, 'logout', 'one session kills another')
                            """),
                            {
                                'person_id': person_id,
                                'session_id': killed_session_id,
                                'client_ip_address': req.client_IP_address})

                    log.info(
                        "Updated LOGOUT user_activity_logs with {0} new rows for "
                        "person {1}.".format(len(session_IDs_killed), person_id))

                # Create a session for this user.
                person_id = result.person_id

                si = session.SessionInserter(person_id)
                session_id = si.execute(self.pgconn).session_id

                # Now, log that we logged in this user.
                cursor.execute(textwrap.dedent("""
                    insert into user_activity_logs
                    (person_id, session_id, client_ip_address, action, extra_notes)
                    values
                    (%(person_id)s, %(session_id)s, %(client_ip_address)s, 'login', 'normal login')
                    """), {
                        'person_id': person_id,
                        'session_id': session_id,
                        'client_ip_address':req.client_IP_address})

                log.info("Inserted LOGIN user_activity_log for {0}.".format(person_id))

                #check if it has been 90 days since the last password change

                ninety = result.date_password_changed + datetime.timedelta(days=90)

                if datetime.datetime.now() > ninety:
                    cursor.execute(textwrap.dedent("""
                        update people set person_status ='change password after 90 days'
                        where person_id = %(person_id)s
                         """),
                       {'person_id': person_id})

                    resp = Response.relative_redirect(
                        '/me?90days=true')
                    resp.set_session_cookie(session_id, self.config_wrapper.app_secret)
                    return resp

                if req.redirect_cookie:

                    resp = Response.redirect(req.redirect_cookie)
                    resp.expire_redirect_cookie()

                elif result.is_superuser:

                    resp = Response.relative_redirect(
                        '/view-accounts')

                else:
                    resp = Response.relative_redirect('/')

                resp.set_session_cookie(session_id,
                    self.config_wrapper.app_secret)

                if session_IDs_killed:
                    resp.set_news_message_cookie('We logged you out of another session')

                else:
                    cursor2 = self.cw.get_pgconn().cursor()

                    cursor2.execute(textwrap.dedent("""
                      select inserted
                      from horsemeat_sessions
                      where person_id = %(person_id)s
                      and expires < current_timestamp
                      order by inserted desc
                      limit 1
                      """), {'person_id': person_id})

                    previous_login_session = cursor2.fetchone()

                    #reset the number of failed attempts to 0
                    la = loginattempt.FailedLoginAttempt()
                    la.reset_failed_attempt(self.pgconn,person_id)

                    if previous_login_session:

                        news_msg = textwrap.dedent("""
                            Welcome back!  You previously logged in on {0}.
                            Contact support if that is incorrect.
                            """).format(
                                previous_login_session.inserted.strftime(
                                    "%A, %B %d, %Y %I:%M %P"))

                    else:
                        news_msg = 'Welcome back!'

                    resp.set_news_message_cookie(news_msg)

                return resp

    def scrub(self, req):

        errors, values = dict(), dict()

        if 'email_address' not in req.parsed_body:
            errors['email_address'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:

            email_address = req.parsed_body['email_address'][0]
            values['email_address'] = email_address

        if 'password' not in req.parsed_body:
            errors['password'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:

            password = req.parsed_body['password'][0]
            values['password'] = password

        return errors, values

class AuthenticatorJSON(Handler):

    """
    Check the submitted email address and password vs the database

    This is the same as authhandlers login, but json flavor

    The important part is values contains a key 'success';
    if the login is good, this should be true, otherwise false

    values = {'success':True}, errors = None

    else

    values = {'success':False, errors = {'general' = 'error here'}

    consider combining?
    """

    def route(self,req):
        if req.line_one == 'POST /json/login':
            return self.handle

    def handle(self, req):


        errors, values = self.scrub(req)

        # Check that we got all required data.
        if errors:

            cursor = self.pgconn.cursor()

            errors['success'] = False

            cursor.execute(textwrap.dedent("""
            select person_id
            from people p
            where email_address = %(email_address)s
            and (person_status = 'confirmed' or person_status='needs to sign eula' or person_status='locked out')

            """), values)

            result = cursor.fetchone()

            if not result:
                person_id = result[0]
                try:
                    failed_login = loginattempt.FailedLoginAttempt.insert_failed_attempt(self.pgconn,person_id)

                    num_of_failed_login = loginattempt.FailedLoginAttempt.get_number_of_attempts(self.pgconn,person_id)

                    errors['numberofattemptedlogins'] = str(num_of_failed_login.number_of_attempts)
                    if num_of_failed_login == 4:
                        errors['general'] = "You have failed to login 4 times. The next unsuccesfully attempt will lock you out."

                    if num_of_failed_login >= 5:
                        errors['general'] = "This account has been locked due to too many attempts. Please contact your admininstrator. "
                    else:
                        errors['general'] = "This email and password aren't right."
                except Exception as ex:

                    log.exception(ex)
                    return self.not_found(req)



            return Response.json(dict(errors=errors, values=values))

        # Check if that email address is in the user table.  Don't say
        # that the email address is missing though; that would make it
        # easy for somebody to guess valid email addresses.

        cursor = self.pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select person_id
            from people
            where email_address = %(email_address)s

            and salted_hashed_password = crypt(
                %(password)s,
                salted_hashed_password)

            and (person_status = 'confirmed' or person_status='needs to sign eula' or person_status='locked out')

            """), values)

        result = cursor.fetchone()

        if not result:

            num_of_failed_login = int(req.parsed_body['attemptedLogins'][0])
            errors['numberofattemptedlogins'] = num_of_failed_login + 1

            if num_of_failed_login == 4:
                errors['general'] = "You have failed to login 4 times. The next unsuccesfully attempt will lock you out."

            if num_of_failed_login >= 5:
                errors['general'] = "This account has been locked due to too many attempts. Please contact your admininstrator. "
            else:
                errors['general'] = "This email and password aren't right."

            errors['success'] = False


            resp = Response.json(dict(errors=errors, values=values))

            resp.set_session_cookie(session_id,
                    self.config_wrapper.app_secret)
        # Create a session for this user.
        person_id = result['person_id']

        si = session.SessionInserter(person_id)
        session_id = si.execute(self.pgconn)['session_id']

        values = {'success':'true'}
        resp = Response.json(dict(values=values, errors=errors))

        resp.set_session_cookie(session_id,
            self.config_wrapper.app_secret)

        #In case we're on cross domains (which we prolly
        #will be, lets set the cookie into the json
        #This is kind of hacky right now

        loginattempt.FailedLoginAttempt.insert_failed_attempt(self.pgconn,person_id)

        body = json.loads(resp.body)
        #first header is Content Type, second is session cookie
        body['values']['Set-Cookie'] = resp.headers[1][1]

        resp.body = json.dumps(body)

        return resp

    def scrub(self, req):

        errors, values = dict(), dict()

        if 'email_address' not in req.parsed_body:
            errors['email_address'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:

            email_address = req.parsed_body['email_address'][0]
            values['email_address'] = email_address

        if 'password' not in req.parsed_body:
            errors['password'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:

            password = req.parsed_body['password'][0]
            values['password'] = password

        return errors, values


class Logout(Handler):

    route_strings = set(['POST /logout'])

    route = Handler.check_route_strings

    def handle(self, req):

        """
        Look up the session.

        Update the session and set the expires column to right now.

        Reply with a redirect back to /login and add a custom news
        message.
        """

        if not req.user:
            return Response.relative_redirect("/login")

        cursor = self.pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            update horsemeat_sessions
            set expires = current_timestamp
            where session_id = (%s)
            """), [req.session.session_id])

        cursor.execute(textwrap.dedent("""
            insert into user_activity_logs
            (person_id, session_id, client_ip_address, action, extra_notes)
            values
            (%(person_id)s, %(session_id)s, %(client_ip_address)s, 'logout', 'normal logout')
            """),
            {
                'person_id': req.user.person_id,
                'session_id': req.session.session_id,
                'client_ip_address': req.client_IP_address})

        log.info(
            "Updated LOGOUT user_activity_logs with 1 new row for "
            "person {0}.".format(req.user.person_id))

        log.info("User id {0} just logged out.".format(req.user.person_id))

        resp = Response.redirect('{web_host}/login'.format(
            web_host=self.cw.web_host))

        resp.set_news_message_cookie('You are signed out!')

        return resp

class ForgotPasswordForm(Handler):

    def route(self, req):

        if req.line_one in (
            'GET /send-password-reset-email-link',
            'GET /send-reset-email-link',
            'GET /forgot-password'):

            return self.handle

    def handle(self, req):

        tmpl = self.jinja2_environment.get_template(
            'auth/send-password-reset-email.html')

        return Response.template(tmpl)

class PasswordResetLinkSender(Handler):

    """
    Send an email to the registered user with a link to the
    reset-password form.

    Requests should look like::

        POST /send-password-reset-email

        email_address=matt@tplus1.com

    """

    route_strings = set(['POST /send-password-reset-email'])

    route = Handler.check_route_strings

    def handle(self, req):

        """
        Insert an email into the email queue or redraw the form.
        """

        errors, values = self.scrub(req)

        if errors:

            tmpl = self.jinja2_environment.get_template(
                'auth/send-password-reset-email.html')

            return Response.template(tmpl, errors=errors, values=values)

        # If the email is in the database, insert an email into the
        # email message queue.

        # If this email is not in the database, don't send a
        # reset-password link, but pretend like we did, so that mean
        # guys can't guess if they found a registered email.

        cursor = self.pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select email_address
            from people
            where email_address = (%s)
            """), [values['email_address']])

        result = cursor.fetchone()

        if result:

            # Insert an email into the email queue.
            emi = message.EmailMessageInserter(
                values['email_address'],
                'forgot password').execute(self.pgconn)

            es = message.EmailSender(
                self.cw,
                emi)

            es.send_email()

        return Response.redirect('{web_host}/check-your-email'.format(
            web_host=self.cw.web_host),
            'OK, we sent an email to {email_address}'.format(**values))


    def scrub(self, req):

        errors, values = dict(), dict()

        # Make sure that the submitted email_address looks like a valid
        # email.  Don't worry if it is in the database.

        if 'email_address' not in req.parsed_body:
            errors['email_address'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:

            email_address = req.parsed_body['email_address'][0]
            values['email_address'] = email_address

            # Make sure the submitted value looks like an email address.
            matches = re.match(r'.+@.+\..+', email_address)

            if not matches:
                errors['email_address'] = "Sorry, this doesn't look like a good email address"

        return errors, values


class PasswordResetForm(Handler):

    """
    Either of these will work::

        GET /password-reset?email_address=matt@tplus1.com&nonce=c3ad4e4c-60aa-49bc-9b82-e99262d408b3

        GET /reset-password?email_address=matt@tplus1.com&nonce=c3ad4e4c-60aa-49bc-9b82-e99262d408b3

    """

    route_strings = set([
        'GET /password-reset',
        'GET /reset-password'])

    route = Handler.check_route_strings

    def handle(self, req):

        errors, values = self.scrub(req)

        return Response.tmpl(
            'auth/reset-password.html',
            errors=errors, values=values)

    def scrub(self, req):

        errors, values = dict(), dict()

        # Extract email.

        if 'email_address' in req.parsed_QS:

            email_address = req.parsed_QS['email_address'][0]
            values['email_address'] = email_address

            # Make sure the submitted value looks like an email address.
            matches = re.match(r'.+@.+\..+', email_address)

            if not matches:
                errors['email_address'] = "Sorry, this doesn't look like a good email address"

        # Extract nonce.
        if 'nonce' in req.parsed_QS:

            nonce = req.parsed_QS['nonce'][0]

            try:
                values['nonce'] = uuid.UUID(nonce)

            except ValueError, ex:
                log.exception(ex)
                errors['nonce'] = "This doesn't look right"
                values['nonce'] = nonce

        # Check for password 1.

        if 'password1' in req.parsed_QS:
            values['password1'] = req.parsed_QS['password1'][0]

        # Check for password 2.

        if 'password2' in req.parsed_QS:
            values['password2'] = req.parsed_QS['password2'][0]

        # Now verify password 1 and password 2 are the same.

        if ('password1' in values
            and 'password2' in values and values['password1'] != values['password2']):

            errors['password2'] = "This doesn't match the first password!"
            errors['general'] = "Passwords do not match!"

        return errors, values

class ResetPassword(Handler):

    """
    This is for when people forgot their password.  We check for an
    email address and a nonce.

    For people that are logged in an want to change their password, look
    at ChangePassword

    Handle requests like::

        POST /reset-password

        email_address=matt@tplus1.com\
        &nonce=asdfdasdasfasfd\
        &password1=abcdef\
        &password2=abcdef

    """

    def route(self, req):

        if req.line_one == 'POST /reset-password':
            return self.handle

    def handle(self, req):

        errors, values = ResetPasswordScrubber(self.config_wrapper,
        self.pgconn, req).scrub()

        if errors:

            tmpl = self.jinja2_environment.get_template(
                'auth/reset-password.html')

            return Response.template(tmpl, errors=errors, values=values)


        else:

            pu = user.PasswordUpdater(values['email_address'], values['password'])
            pu.update_password(self.pgconn)

            pw_history = password_history(self.pgconn, values['email_address'])
            pw_history.insert_password_history(values['password'])


        return Response.redirect(
            '{web_host}/login'.format(web_host=self.cw.web_host),
            'Log in with your new password')


class ResetPasswordScrubber(object):

    def __init__(self, config_wrapper, pgconn, req):
        self.req = req
        self.config_wrapper = config_wrapper
        self.pgconn = pgconn
        self.errors = dict()
        self.values = dict()

    def scrub_email(self):

        if 'email_address' not in self.req.parsed_body:
            self.errors['email_address'] = 'This is a required field!'
            self.errors['general'] = 'You are missing at least one required fields!'

        else:

            email_address = self.req.parsed_body['email_address'][0]
            self.values['email_address'] = email_address

            # Make sure the submitted value looks like an email address.
            matches = re.match(r'.+@.+\..+', email_address)

            if not matches:
                self.errors['email_address'] = "Sorry, this doesn't look like a good email address"

        return self.errors, self.values

    def scrub_nonce(self):

        if 'nonce' not in self.req.parsed_body:
            self.errors['nonce'] = 'This is a required field!'
            self.errors['general'] = 'You are missing at least one required fields!'

        else:

            nonce = self.req.parsed_body['nonce'][0]

            try:
                self.values['nonce'] = uuid.UUID(nonce)

            except ValueError, ex:
                log.exception(ex)
                self.errors['nonce'] = "This doesn't look right"
                self.values['nonce'] = nonce

        return self.errors, self.values

    def scrub_passwords(self):

        # Check passwords.
        if 'password1' not in self.req.parsed_body:
            self.errors['password1'] = 'This is a required field!'
            self.errors['general'] = 'You are missing at least one required fields!'

        else:
            self.values['password1'] = self.req.parsed_body['password1'][0]

        # Check for password 2.

        if 'password2' not in self.req.parsed_body:
            self.errors['password2'] = 'This is a required field!'
            self.errors['general'] = 'You are missing at least one required fields!'

        else:
            self.values['password2'] = self.req.parsed_body['password2'][0]

        # Make sure the two versions match.

        if ('password1' in self.values
            and 'password2' in self.values
            and self.values['password1'] != self.values['password2']):

            self.errors['password2'] = "This doesn't match the first password!"
            self.errors['general'] = "Passwords do not match!"

        elif ('password1' in self.values
            and 'password2' in self.values
            and self.values['password1'] == self.values['password2']):

            self.values['password'] = self.values['password1']

    def check_password_history(self):

        pw_history = user.PasswordHistory(self.pgconn,email_address=self.values['email_address'])
        #for now just check
        pass_history = pw_history.check_password_history(self.values['password'],insert_history_record=False)

        if pass_history==True:
            self.errors['general'] = 'Sorry, this password has been used within the last year!'

    def check_database(self):

        """
        Verify this user really did ask for a password reset.
        """

        cursor = self.pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select email_message_queue_id
            from email_message_queue
            where (recipient_email_address = %(email_address)s AND nonce = %(nonce)s
            AND (message_type='forgot password' OR message_type='notify user of too many password attempts'
            OR message_type='reset locked user'))
            """), {'email_address': self.values['email_address'],'nonce' : self.values['nonce']})

        result = cursor.fetchone()

        if not result:
            self.errors['general'] = 'Sorry! please contact the system admin.'

    def scrub_challenge_questions(self):

        """
        Verify the challenge question
        """


        if 'challenge_question' not in self.req.parsed_body:
            self.errors['challenge_question'] = 'This is a required field!'
            self.errors['general'] = 'You are missing at least one required fields!'

        else:
            self.values['challenge_question'] = self.req.parsed_body['challenge_question'][0]

        if 'challenge_question_answer' not in self.req.parsed_body:
            self.errors['challenge_question_answer'] = 'This is a required field!'
            self.errors['general'] = 'You are missing at least one required fields!'

        else:
            self.values['challenge_question_answer'] = self.req.parsed_body['challenge_question_answer'][0]

        cursor = self.pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            Select exists(select challenge_question, challenge_question_answer
            from people
            where (challenge_question, challenge_question_answer,email_address)
            = (%s, %s,%s))
            """), [self.values['challenge_question'], self.values['challenge_question_answer'], self.values['email_address']])

        result = cursor.fetchone()




        if result[0]==False:
            self.errors['general'] = 'Challenge question and answer do not match!'

    def scrub(self):

        self.scrub_email()

        self.scrub_nonce()

        self.scrub_passwords()

        self.scrub_challenge_questions()

        self.check_password_history()

        if not self.errors:

            self.check_database()

        return self.errors, self.values


class FormResendConfirmEmail(Handler):

    def route(self, req):

        if req.line_one in (
            'GET /send-new-confirm-email',
            'GET /resend-confirm-email'):
            return self.handle


    def handle(self, req):

        errors, values = self.scrub(req)

        tmpl = self.jinja2_environment.get_template('auth/resend-confirm-email.html')
        return Response.template(tmpl, errors=errors, values=values)

    def scrub(self, req):

        errors, values = dict(), dict()

        if 'email_address' in req.parsed_body:

            email_address = req.parsed_body['email_address'][0]
            values['email_address'] = email_address

            # Make sure the submitted value looks like an email address.
            matches = re.match(r'.+@.+\..+', email_address)

            if not matches:
                errors['email_address'] = ("Sorry, this doesn't look "
                    "like a good email address")

            # Make sure that this email is ALREADY in the database.

            if not errors:

                cursor = self.pgconn.cursor()

                cursor.execute(textwrap.dedent("""
                    select email_address
                    from people
                    where email_address = (%s)
                    and person_status = 'started registration'
                    """), [email_address])

                if not cursor.rowcount:
                    errors['general'] = ('Either you already confirmed '
                        'your email or you never registered.')

        return errors, values


class SendNewConfirmEmail(Handler):

    """
    Use this handler when you need to re-send the confirmation email,
    but the user already exists.
    """

    def route(self, req):

        if req.line_one == 'POST /send-new-confirm-email':
            return self.handle


    def handle(self, req):

        errors, values = self.scrub(req)

        if errors:

            tmpl = self.jinja2_environment.get_template('auth/resend-confirm-email.html')
            return Response.template(tmpl, errors=errors, values=values)

        else:

            # TODO: use something different!
            random_password = '{0}{1}{2}{3}{4}{5}'.format(
                random.choice(string.uppercase),
                random.choice(string.digits),
                random.choice(string.uppercase),
                random.choice(string.digits),
                random.choice(string.uppercase),
                random.choice(string.digits))

            pu = user.PasswordUpdater(
                values['email_address'],
                random_password)

            pu.update_password(self.pgconn)

            # Insert an email into the email queue.
            email_message = message.EmailMessageInserter(
                values['email_address'],
                'registration').execute(self.pgconn)

            # And now immediately process that email.
            es = message.EmailSender(
                self.cw,
                email_message)

            es.send_email()

            if req.user and req.user.is_superuser:
                return Response.relative_redirect('/view-accounts',
                    'New confirmation email sent to {email_address}.'.format(**values))

            else:
                return Response.relative_redirect('/check-your-email')

    def scrub(self, req):

        errors, values = dict(), dict()

        if 'email_address' not in req.parsed_body:
            errors['email_address'] = 'This is a required field!'
            errors['general'] = 'You are missing at least one required fields!'

        else:

            email_address = req.parsed_body['email_address'][0]
            values['email_address'] = email_address

            # Make sure the submitted value looks like an email address.
            matches = re.match(r'.+@.+\..+', email_address)

            if not matches:
                errors['email_address'] = ("Sorry, this doesn't look "
                    "like a good email address")

            # Make sure that this email is ALREADY in the database.

            if not errors:

                cursor = self.pgconn.cursor()

                cursor.execute(textwrap.dedent("""
                    select email_address
                    from people
                    where email_address = (%s)
                    and person_status = 'started registration'
                    """), [email_address])

                if not cursor.rowcount:
                    errors['general'] = ('Either you already confirmed '
                        'your email or you never registered.')

        return errors, values

class ChangePassword(Handler):

    """
    Handle requests from authenticated users to change their password::

        POST /change-password

        old_password=1234567&password1=abcdef&password2=abcdef

    For people that forgot their password and need to reset it, look at
    ResetPassword.

    """

    def route(self, req):

        if req.line_one == 'POST /change-password' and req.user:

            return self.handle


    def handle(self, req):

        raw_data, errors, values = self.scrub(req)

        #pw_history = user.PasswordHistory(self.pgconn, person_id=values['person_id'])
        #pass_history = pw_history.check_password_history(values['password'],insert_history_record=False)

        #if pass_history==True:
        #    errors['general'] = 'Sorry, this password has been used in the past year.'

        if errors:

            tmpl = self.j.get_template('auth/me.html')

            return Response.template(
                tmpl,
                errors=errors,
                values=values)

        else:

            cursor = self.pgconn.cursor()

            cursor.execute(textwrap.dedent("""
                update people

                set salted_hashed_password = crypt(
                    %(password)s,
                    gen_salt('md5')),
                    date_password_changed=current_timestamp,
                    person_status='confirmed'
                where person_id = %(person_id)s RETURNING salted_hashed_password
                """), values)


            result = cursor.fetchone()


            new_hashed_password = result.salted_hashed_password

            log.info("password history salt password for {0}.".format(new_hashed_password))

            pw_history = user.PasswordHistory(self.pgconn, person_id=values['person_id'])
            pass_history = pw_history.insert_password_history(new_hashed_password)


            log.info("Inserted password history for {0}.".format(values['person_id']))

            return Response.redirect(
                '{0}/me'.format(self.cw.web_host),
                'OK, password updated!')



    def scrub(self, req):

        cps = scrubbers.ChangePasswordScrubber(self.pgconn, req)
        raw_data, errors, values = cps.scrub()
        return raw_data, errors, values


class PickPasswordForm(Handler):

    def route(self, req):

        if req.line_one == 'GET /pick-password':
            return self.handle

    def handle(self, req):

        if not req.user:
            return self.prompt_for_login(req)

        elif req.user.person_status != 'needs to pick password':
            return self.not_found(req)

        else:
            return Response.tmpl('auth/pick_password.html')

class SetPassword(Handler):

    def route(self, req):

        if req.line_one == 'POST /set-password':
            return self.handle

    def handle(self, req):

        if not req.user:
            return self.prompt_for_login(req)

        elif req.user.person_status != 'needs to pick password':
            return self.not_found(req)

        else:

            raw_data, errors, values = self.scrub(req)

            if errors:

                return Response.tmpl(
                    'auth/pick_password.html',
                    raw_data=raw_data,
                    errors=errors,
                    values=values)

            else:

                self.update_password(values, initial_registration=True)

                #return Response.relative_redirect('/my-binders',
                 #   'password set!')
                return Response.relative_redirect('/sign-eula',
                    'password set!')


    def scrub(self, req):

        raw_data, errors, values = dict(), dict(), dict()

        try:
            values['person_id'] = req.user.person_id
            values['pw1'] = req.parsed_body['pw1'][0]
            values['pw2'] = req.parsed_body['pw2'][0]

            if values['pw1'] != values['pw2']:
                errors['pw2'] = 'Mismatch'

            self.check_strong_password(raw_data, errors, values)

        except Exception as ex:
            log.exception(ex)
            errors['general'] = 'Sorry, try again'

        return raw_data, errors, values

    def check_strong_password(self, raw_data, errors, values):

        password = values['pw1']
        #strength = ['Blank', 'Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']
        score = 0

        if len(password) < 8 or len(password) < 1:
            score = score + 1

        if len(password) >= 8:
            score = score + 1
            log.debug(score)
        if len(password) >=10:
            score = score + 1

        if re.search('\d+',password):
            score = score + 1
        if re.search('[a-z]',password) and re.search('[A-Z]', password):
            score = score + 1
        if re.search('.[!,@,#,$,%,^,&,*,?,_,~,-,(,)]', password):
            score = score + 1


        if score <= 2:
            errors['pw1'] = 'Password must be a strong password! The password must be minimum of eight alphanumeric characters including a number or symbol'
            errors['general'] = 'Sorry, you have some bad data'

        return raw_data, errors, values


    def update_password(self, values, initial_registration=None):

        cursor = self.pgconn.cursor()

        if initial_registration:
             cursor.execute(textwrap.dedent("""
                    update people
                    set salted_hashed_password = crypt(%s, gen_salt('md5')),
                    person_status = 'needs to sign eula'
                    where person_id = (%s)
                    and person_status = 'needs to pick password'
                     RETURNING salted_hashed_password"""), [values['pw1'], values['person_id']])
        else:
            cursor.execute(textwrap.dedent("""
                update people
                set salted_hashed_password = crypt(%s, gen_salt('md5')),
                person_status = 'confirmed'
                where person_id = (%s)
                and person_status = 'needs to pick password'
                 RETURNING salted_hashed_password"""), [values['pw1'], values['person_id']])


        result = cursor.fetchone()

        new_hashed_password = result.salted_hashed_password

        pw_history = user.PasswordHistory(self.pgconn, person_id=values['person_id'])
        pass_history = pw_history.insert_password_history(new_hashed_password)



        log.info("Inserted password history for {0}.".format(values['person_id']))

        return cursor

class ChangeName(Handler):

    """
    Handle requests from authenticated users to change their name::

        POST /change-displayname

    """

    def route(self, req):

        if req.line_one == 'POST /update-name' and req.user:

            return self.handle


    def handle(self, req):

        raw_data, errors, values = self.scrub(req)

        if errors:

            tmpl = self.j.get_template('auth/me.html')

            return Response.template(
                tmpl,
                errors=errors,
                values=values)

        else:

            cursor = self.pgconn.cursor()

            cursor.execute(textwrap.dedent("""
                update people

                set display_name = %(displayname)s

                where person_id = %(person_id)s
                """), values)

            return Response.relative_redirect(
                '/me',
                'OK, name changed to "{0}"'.format(values['displayname']))


    def scrub(self, req):
        raw_data, errors, values = dict(), dict(), dict()

        try:
            values['displayname'] = req.parsed_body['displayname'][0]
            values['person_id'] = req.user.person_id

        except Exception as ex:

            errors['general'] = 'Sorry, bad request'

        return raw_data, errors, values
