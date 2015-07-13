# /usr/bin/env python
# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf8:

import argparse
import logging
import os
import textwrap
import subprocess
import sys
import yaml

from rtapebbletest import configwrapper

log = logging.getLogger('rtapebbletest.upgrade_database')

def set_up_arguments():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        'yaml_file_name',
        help='This is your config file')

    ap.add_argument(
        'script_order_file',
        nargs='?',
        default=None,
        help='Lists order to run scripts (default is script-run-order.yaml)')

    ap.add_argument('--dry-run', action='store_true',
        help='Do not actually update anything in the database.')

    return ap.parse_args()

def find_new_scripts(script_order, already_ran_scripts):

    """
    Generator that yields strings of script names that still need to be
    run.
    """

    for sql_script_name in script_order:

        log.debug("Checking script {0}...".format(sql_script_name))

        if sql_script_name not in already_ran_scripts:

            log.debug("Need to run {0}...".format(sql_script_name))

            yield sql_script_name

def get_scripts_already_ran(pgconn):

    """
    Return a set of tuples of scripts already ran in this database.

    I'm using a set for faster lookup, not that it really matters.
    """

    cursor = pgconn.cursor()

    cursor.execute(textwrap.dedent("""
        select script_path
        from rtapebbletest_schema_version
        """))

    return {row.script_path for row in cursor}


def run_script(pgconn, path_to_script):

    cursor = pgconn.cursor()

    try:

        cursor.execute(textwrap.dedent("""
            insert into rtapebbletest_schema_version
            (script_path, script_contents)
            values
            (
                %(path_to_script)s,
                %(script_contents)s
            )
            """),
            {
                'path_to_script': path_to_script,
                'script_contents': open(path_to_script, 'r').read()
            })

        # Next, run the SQL script, in single-transaction mode, so
        # hopefully, everything will get rolled back if something goes
        # wrong.

        env = os.environ.copy()
        env[b'PGPASSWORD'] = cw.database_password

        # Use ON_ERROR_STOP so that
        # a non zero error code so we can catch the Exception

        result = subprocess.check_call([
                "psql",
                "-U",
                cw.database_user,
                "-h",
                cw.database_host,
                "-d",
                cw.database_name,
                "--single-transaction",
                "--set",
                "ON_ERROR_STOP=1",
                "-f",
                path_to_script,
            ],
            env=env)

        log.debug('result is {0}'.format(result))


    except subprocess.CalledProcessError as ex:

        log.critical("script {0} blew up!".format(path_to_script))

        pgconn.rollback()
        raise Exception("A script blew up, let's not do anything else past this.")

    else:

        pgconn.commit()


def find_script_run_order_file():

    p = os.path.dirname(os.path.abspath(__file__))

    guess = os.path.join(p, 'script-run-order.yaml')

    if os.path.exists(guess):
        return guess

    else:
        raise Exception("Could not find a script-run-order.yaml file!")


def maybe_run_setup_script(pgconn, setup_script):

    """
    Check if the rtapebbletest_schema_version table exists.

    If it does not, run the initial setup script.
    """

    cursor = pgconn.cursor()

    cursor.execute(textwrap.dedent("""
        select exists(
            select 1
            from pg_catalog.pg_class
            where relname = 'rtapebbletest_schema_version'
            and relkind = 'r'
        )
        """))

    if cursor.fetchone().exists:
        return

    else:
        log.info("About to create rtapebbletest_schema_version table.")

        env = os.environ.copy()
        env['PGPASSWORD'] = cw.database_password

        subprocess.check_call([
                "psql",
                "-U",
                cw.database_user,
                "-h",
                cw.database_host,
                "-d",
                cw.database_name,
                "--single-transaction",
                "-f",
                setup_script,
            ],
            env=env)

if __name__ == '__main__':

    args = set_up_arguments()

    cw = configwrapper.ConfigWrapper.from_yaml_file_name(
        args.yaml_file_name)

    cw.configure_logging('script')

    cw.create_postgresql_connection(register_composite_types=False)

    if not args.script_order_file:
        args.script_order_file = find_script_run_order_file()

    d = yaml.load(open(args.script_order_file))

    maybe_run_setup_script(
        cw.get_pgconn(),
        d['setup_script'])

    already_ran_scripts = get_scripts_already_ran(cw.get_pgconn())

    for new_script in find_new_scripts(
        d['script_order'],
        already_ran_scripts):
        try:
           run_script(cw.get_pgconn(), new_script)
        except Exception as e:
           log.critical(e)
           break

    log.info("All done!")
