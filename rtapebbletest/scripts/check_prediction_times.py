# vim: set expandtab ts=4 sw=4 filetype=python:

"""
This script should check stale rss feeds and save the latest articles
from each feed
This file should be output to a CSV file with relevant company information
"""
import argparse
import csv
import datetime
import logging
import os
import socket
import string
import sys
import textwrap
import traceback
import urllib2

from rtapebbletest.pg import stops

from rtapebbletest import configwrapper

log = logging.getLogger('rtapebbletest.scripts.check_for_live_bus_times')


if __name__ == "__main__":

    import argparse
    ap = argparse.ArgumentParser('check_for_live_bus_times')

    ap.add_argument('yaml_file_name', help='e.g., dev.yaml')

    args = ap.parse_args()

    cw = configwrapper.ConfigWrapper.\
        from_yaml_file_name(args.yaml_file_name)

    cw.configure_logging()

    pgconn = cw.get_pgconn()

    stops = stops.Stop.all_stops(pgconn)

    log.debug("Found {0} stops to check".format(len(stops)))
    for stop in stops:

        log.debug("Now checking stop times for {0}".format(stop))

        try:
            stop.check_and_insert_stop_predictions(pgconn)

        except Exception as e:
            log.error(e)
            pgconn.rollback()
            continue

        finally:
            pgconn.commit()

    # Do final commit to store new articles
    pgconn.commit()

    log.debug("Stop checking completed")
