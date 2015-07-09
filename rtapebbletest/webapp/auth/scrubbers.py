# vim: set expandtab ts=4 sw=4 filetype=python:

import logging
import textwrap
import re

from rtapebbletest.model.user import PasswordHistory

from rtapebbletest.webapp.framework import scrubber

log = logging.getLogger(__name__)

class AuthScrubber(scrubber.Scrubber):

    """
    All the auth-related scrubbers are here.  Different subclasses pick
    and choose which ones to run.
    """

    def extract_password1_from_post(self, raw_data, errors, values):

        if 'password1' in self.req.parsed_body:
            values['password1'] = self.req.parsed_body['password1'][0]

        else:
            errors['password1'] = 'This is a required field!'
            errors['general'] = 'Sorry, you have some bad data'

        return raw_data, errors, values


    def extract_password2_from_post(self, raw_data, errors, values):

        if 'password2' in self.req.parsed_body:
            values['password2'] = self.req.parsed_body['password2'][0]

        else:
            errors['password2'] = 'This is a required field!'
            errors['general'] = 'Sorry, you have some bad data'

        return raw_data, errors, values


    def verify_passwords_match(self, raw_data, errors, values):

        if not errors and values['password1'] != values['password2']:
            errors['password2'] = 'This password doesn\'t match!'

        return raw_data, errors, values


    def extract_old_password_from_post(self, raw_data, errors, values):

        if 'old_password' in self.req.parsed_body:
            values['old_password'] = self.req.parsed_body['old_password'][0]

        else:
            errors['old_password'] = 'This is a required field!'
            errors['general'] = 'Sorry, you have some bad data'

        return raw_data, errors, values

    def extract_person_id_from_session(self, raw_data, errors, values):

        log.debug('errors is {0}.'.format(errors))

        if not errors:

            if not self.req.session:
                errors['general'] = "No session!"

            elif not self.req.user:
                errors['general'] = "Not logged in!"

            else:
                values['person_id'] = self.req.user.person_id

        return raw_data, errors, values


    def verify_password_history(self, raw_data, errors, values):

        if not errors:

            pw_history = PasswordHistory(self.pgconn, person_id=values['person_id'])
            log.debug("Password for password history for {0}.".format(values['password1']))
            pass_history = pw_history.check_password_history(values['password1'],insert_history_record=False)

            if pass_history==True:
                errors['general'] = 'Sorry, this password has been used in the past year.'

        return raw_data, errors, values


    def verify_old_password_is_correct(self, raw_data, errors, values):

        if not errors:

            cursor = self.pgconn.cursor()

            cursor.execute(textwrap.dedent("""
                select person_id
                from people
                where person_id = %(person_id)s
                and salted_hashed_password = crypt(
                %(old_password)s,
                salted_hashed_password)
                """),
                dict(
                    person_id=values['person_id'],
                    old_password=values['old_password']))

            if not cursor.rowcount:
                # errors['general'] = 'Sorry, you have some bad data'
                errors['old_password'] = 'Sorry, this is not correct'

        return raw_data, errors, values

    def extract_biography_from_post(self, raw_data, errors, values):

        if 'biography' in self.req.parsed_body:
            values['biography'] = self.req.parsed_body['biography'][0]

        else:
            errors['biography'] = 'This is a required field!'
            errors['general'] = 'Sorry, you have some bad data'

        return raw_data, errors, values

    def check_password(self, raw_data, errors, values):

        password = values['password1']
        #strength = ['Blank', 'Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']
        score = 1

        #if len(password) < 1:
        #    return strength[0]
        #if len(password) < 4:
        #    return strength[1]

        log.debug(password)

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
            errors['password1'] = 'Password must be a strong password! The password must be minimum of eight alphanumeric characters including a number or symbol'
            errors['general'] = 'Sorry, you have some bad data'

        return raw_data, errors, values

class ChangePasswordScrubber(AuthScrubber):

    def scrub(self):

        raw_data, errors, values = dict(), dict(), dict()

        # Remember that python passes errors and values by
        # references so each of these methods are altering the errors
        # and values dictionaries.

        self.extract_password1_from_post(raw_data, errors, values)
        self.extract_password2_from_post(raw_data, errors, values)
        self.check_password(raw_data, errors, values)
        self.verify_passwords_match(raw_data, errors, values)
        self.extract_old_password_from_post(raw_data, errors, values)
        self.extract_person_id_from_session(raw_data, errors, values)
        self.verify_old_password_is_correct(raw_data, errors, values)
        self.verify_password_history(raw_data,errors,values)

        if not errors:

            # Now assign the good values.
            values['password'] = values['password1']

        log.debug('errors at the end of scrub is {0}.'.format(errors))

        return raw_data, errors, values

class UpdateBiographyScrubber(AuthScrubber):

    def scrub(self):

        raw_data, errors, values = dict(), dict(), dict()

        self.extract_person_id_from_session(raw_data, errors, values)
        self.extract_biography_from_post(raw_data, errors, values)

        return raw_data, errors, values

class UpdateContactInfoScrubber(AuthScrubber):

    def scrub(self):

        raw_data, errors, values = dict(), dict(), dict()

        self.extract_person_id_from_session(raw_data, errors, values)

        for field in ['phone_number_one', 'phone_number_two',
            'twitter_page',
            'facebook_page',
            'pinterest_page',
            'email_address',
            'street_address_line_one',
            'street_address_line_two',
            'city',
            'state',
            'zipcode']:

            self.generic_extract(raw_data, errors, values, field,
                self.req.parsed_body, required_field=False,
                converter=self.convert_empty_strings_to_None)

        return raw_data, errors, values

class UpdateLocationScrubber(AuthScrubber):

    def scrub(self):

        raw_data, errors, values = dict(), dict(), dict()

        self.extract_person_id_from_session(errors, values)

        for field in ['latitude', 'longitude']:

            self.generic_extract(raw_data, errors, values, field,
                self.req.parsed_body, required_field=True,
                converter=float)

        log.debug('errors at the end of scrub is {0}.'.format(errors))

        return raw_data, errors, values

