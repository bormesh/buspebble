#vim: set expandtab ts=4 sw=4 filetype=python:

import datetime
import logging

from rtapebbletest.webapp.framework.handler import Handler
from rtapebbletest.webapp.framework.response import Response

from rtapebbletest.pg import stops

log = logging.getLogger(__name__)

module_template_prefix = 'rtapebbletest'
module_template_package = 'rtapebbletest.webapp.rtapebbletest.templates'

__all__ = ['Splash', 'PredictedStopTime']

class Splash(Handler):

    route_strings = set(['GET /'])
    route = Handler.check_route_strings

    def handle(self, req):
        return Response.tmpl('rtapebbletest/splash.html')

class PredictedStopTime(Handler):

    route_strings = set([
            "GET /api/prediction/",
            "GET /api/prediction"
            ])

    route = Handler.check_route_strings

    def handle(self, req):

        stop_id = req.wz_req.args.get("stop", 0)

        pgconn = self.cw.get_pgconn()

        stop = stops.Stop.by_stop_id(pgconn, stop_id)

        prediction, scheduled = stop.get_my_next_predicted_stop_time(pgconn)

        if not prediction:
            prediction = ''
            scheduled = stop.get_my_next_scheduled_stop_time(pgconn)
            now = datetime.datetime.now(scheduled.tzinfo)

            scheduled_dt = datetime.datetime.combine(datetime.datetime.now(),
                scheduled)

            minutes_until_bus = (scheduled_dt - now).seconds / 60


        else:
            now = datetime.datetime.now(prediction.tzinfo)
            prediction_dt = datetime.datetime.combine(datetime.datetime.now(),
                prediction)

            minutes_until_bus = (prediction_dt - now).seconds / 60
            prediction = prediction.strftime("%H:%M")

        scheduled = scheduled.strftime("%H:%M")

        return Response.json(dict(
                reply_timestamp=datetime.datetime.now(),
                message="Returning stops for {0}.".format(stop_id),
                success=True,
                minutes_until_bus = minutes_until_bus,
                prediction=prediction,
                scheduled=scheduled))

