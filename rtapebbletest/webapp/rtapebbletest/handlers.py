#vim: set expandtab ts=4 sw=4 filetype=python:

import logging

from rtapebbletest.webapp.framework.handler import Handler
from rtapebbletest.webapp.framework.response import Response

log = logging.getLogger(__name__)

module_template_prefix = 'rtapebbletest'
module_template_package = 'rtapebbletest.webapp.rtapebbletest.templates'

__all__ = ['Splash']

class Splash(Handler):

    route_strings = set(['GET /'])
    route = Handler.check_route_strings

    def handle(self, req):
        return Response.tmpl('rtapebbletest/splash.html')
