# vim: set expandtab ts=4 sw=4 filetype=python:

import logging
import requests
import textwrap

from dateutil import parser

import psycopg2.extras

log = logging.getLogger(__name__)

class StopFactory(psycopg2.extras.CompositeCaster):

    def make(self, values):
        d = dict(zip(self.attnames, values))
        return Stop(**d)


class Stop(object):

    def __init__(self, stop_id, rta_internal_stop_id, title,
        route_id, destination, inserted, updated):

        self.stop_id = stop_id
        self.rta_internal_stop_id = rta_internal_stop_id
        self.title = title
        self.route_id = route_id
        self.destination = destination
        self.inserted = inserted
        self.updated = updated

        # Gotta look these up
        self.rta_internal_route_id = None

    def __repr__(self):
        return '<{0} ({1}:{2})>'.format(
            self.__class__.__name__,
            self.stop_id,
            self.title
            )

    @classmethod
    def by_stop_id(cls, pgconn, stop_id):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select (s.*)::stops as s
            from stops s
            where stop_id = %(stop_id)s
            """), {'stop_id': stop_id})

        if cursor.rowcount:
            stop = cursor.fetchone().s
            stop.look_up_rta_route_id(pgconn)
            return stop

        else:
            raise KeyError("Sorry, couldn't find {0}!".format(
                stop_id))

    @classmethod
    def all_stops(cls, pgconn):

        """
        Returns all the stops
        """

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select (st.*)::stops as s
            from stops st
        """))

        return [row.s.look_up_rta_route_id(pgconn) for row in cursor]

    def look_up_rta_route_id(self, pgconn):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""

            select rta_internal_route_id

            from routes

            where route_id = %(route_id)s


        """), {'route_id':self.route_id})

        # We could also do the whole route object here instead of just
        # internal route id
        self.rta_internal_route_id = cursor.fetchone().rta_internal_route_id
        return self

    def look_up_rta_predictions(self):

        if not self.rta_internal_route_id:
            self.look_up_rta_route_id(pgconn)

        direction_id = '3' if self.destination == 'Richmond' else '14'

        response = requests.post(
            'http://nextconnect.riderta.com/Arrivals.aspx/getStopTimes',
            data = '{"routeID": "%s","directionID":"%s","stopID":"%s", "useArrivalTimes":"false"}' \
                % (self.rta_internal_route_id, direction_id, self.rta_internal_stop_id),
                headers={'Content-Type': ' application/json'})


        crossings = response.json()['d']['stops'][0]['crossings']

        predictions = []

        for crossing in crossings:

            pred = crossing.get('predTime')

            if not pred:
                break

            prediction = parser.parse(pred + crossing.get('predPeriod')).time()

            scheduled = parser.parse(crossing.get('schedTime') + \
                crossing.get('schedPeriod')).time()

            predictions.append({'prediction':prediction,
                'scheduled':scheduled})


        return predictions


    def check_and_insert_stop_predictions(self, pgconn):
        """
        Look up stop times using RTA's next connect URLs.

        We query using a stop id and expect back a json
        dict that has a series of crossings. These
        crossings might or might now have predictions.

        """

        # We expect prediction to be a tuple of predicted time and
        # then scheduled time
        # So predictions is a list
        predictions = self.look_up_rta_predictions()

        if not predictions:
            return None

        for prediction in predictions:

            self.insert_scheduled_time(pgconn,
                prediction['scheduled'])

            self.insert_prediction(pgconn,
                prediction_time=prediction['prediction'],
                scheduled_time=prediction['scheduled'])

        return predictions

    def insert_scheduled_time(self, pgconn, scheduled_time):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""

            insert into scheduled_stops

            (stop_id, scheduled_stop_time)

            select %(stop_id)s, %(scheduled_stop_time)s

            where not exists (
                select scheduled_stop_time from scheduled_stops where
                scheduled_stop_time = %(scheduled_stop_time)s)

       """), {'stop_id':self.stop_id,
           'scheduled_stop_time':scheduled_time})

        return self


    def insert_prediction(self, pgconn, prediction_time, scheduled_time):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""

            insert into predicted_stop_times

            (stop_id, predicted_stop_time, scheduled_stop_time)

            values

            (%(stop_id)s, %(prediction_time)s, %(scheduled_time)s)

        """), {'stop_id': self.stop_id, 'prediction_time':prediction_time,
            'scheduled_time':scheduled_time})

        return self


    def get_my_next_predicted_stop_time(self, pgconn):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""

            select predicted_stop_time, scheduled_stop_time
            from predicted_stop_times
            where stop_id = %(stop_id)s and
            predicted_stop_time > now()::timetz
            and inserted::date = now()::date
            order by inserted desc

            limit 1

       """), {'stop_id':self.stop_id})

        if cursor.rowcount:
            row = cursor.fetchone()

            return (row.predicted_stop_time, row.scheduled_stop_time)

        else:
            return (None, None)

    def get_my_next_scheduled_stop_time(self, pgconn):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""

            select scheduled_stop_time
            from scheduled_stops
            where stop_id = %(stop_id)s and
            scheduled_stop_time > now()::timetz
            order by scheduled_stop_time asc

            limit 1

       """), {'stop_id':self.stop_id})

        if cursor.rowcount:
            return cursor.fetchone().scheduled_stop_time

        else:
            return None




