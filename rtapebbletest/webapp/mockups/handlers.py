# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf8:

import logging
import re
import textwrap

from rtapebbletest.webapp.framework.handler import Handler
from rtapebbletest.webapp.framework.response import Response

__all__ = ['PickupPage', 'SendNewGiftGram','Inbox', 'Sent']

log = logging.getLogger(__name__)

module_template_prefix = 'mockups'
module_template_package = 'rtapebbletest.webapp.mockups.templates'


class Splash(Handler):

    route_strings = set(['GET /'])

    route = Handler.check_route_strings

    def handle(self, req):

        return Response.tmpl('mockups/splash.html')


