# vim: set expandtab ts=4 sw=4 filetype=python:

import logging
import textwrap

import psycopg2.extras

log = logging.getLogger(__name__)

class StopsFactory(psycopg2.extras.CompositeCaster):

    def make(self, values):
        d = dict(zip(self.attnames, values))
        return Stop(**d)


class Stop(object):

    def __init__(self, stop_id, rta_internal_route_id, title,
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
        return '<{0}.{1} ({2}:{3}) at 0x{4:x}>'.format(
            self.__class__.__name__,
            self.stop_id,
            self.title,
            id(self))

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
    def all_stops(cls, pgconn, Stop_id):

        """
        Returns all the stops
        """

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""
            select (s.*)::stops as s
            from stops
        """))

        return [row.s for row in cursor]

    def look_up_rta_route_id(self, pgconn):

        cursor = pgconn.cursor()

        cursor.execute(textwrap.dedent("""

            select rta_internal_route_id

            from routes

            where route_id = %(route_id)s


        """), {'route_id':route_id})

        self.rta_internal_route_id = cursor.fetchone().rta_internal_route_id
        return self.rta_internal_route_id

    def look_up_rta_predictions(self, pgconn):

        cursor = self.pgconn.cursor()

        if not self.rta_internal_route_id:
            self.look_up_rta_route_id(pgconn)

        response = requests.post(
            'http://nextconnect.riderta.com/Arrivals.aspx/getStopTimes',
            data = '{"routeID": "{0}","directionID":"{1}","stopID":"{2}", "useArrivalTimes":"false"}'.\
                format(self.rta_internal_route_id, self.rta_internal_stop_id,
                headers={'Content-Type': ' application/json'}))

        return response


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
        predictions = look_up_rta_predictions(pgconn)

        for prediction in predictions:
            self.insert_prediction(prediction)


        return predictions


    def insert_prediction(self, pgconn, prediction_time, scheduled_time):


        cursor = pgconn.cursor()

        return None

        if cursor.rowcount >0:
            return cursor.fetchone()



