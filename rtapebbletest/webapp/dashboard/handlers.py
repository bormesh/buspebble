# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf8:

"""
Weird stuff.  Have the system tell you about the state of the system.
Django's admin has nothing on this.
"""

import inspect
import logging
import os
import textwrap

from rtapebbletest.webapp.framework.handler import Handler
from rtapebbletest.webapp.framework.response import Response

log = logging.getLogger(__name__)

module_template_prefix = 'dashboard'
module_template_package = 'rtapebbletest.webapp.dashboard.templates'

__all__ = ["HandlerList", "HandlerCode", "Scratch"]


class HandlerList(Handler):

    """
    List all the handlers.
    """

    def route(self, req):

        if req.line_one in [
            'GET /handlers',
            'GET /handler-list']:

            return self.handle

    def handle(self, req):

        handler_list = sorted([h
            for h
            in self.dispatcher.handlers],
            key=lambda x: x.__class__.__name__)

        return Response.tmpl(
            'dashboard/handler-list.html',
            handler_list=handler_list)

class HandlerCode(Handler):

    def route(self, req):

        if req.line_one == 'GET /handler-code':
            return self.handle

    def handle(self, req):

        handler_name = req.parsed_QS['handler_name'][0]

        matching_handler_classes = [h.__class__ for h
            in self.dispatcher.handlers
            if handler_name == h.__class__.__name__]

        log.debug('Found {0} matches for handler name {1}.'.format(
            len(matching_handler_classes),
            handler_name))

        if len(matching_handler_classes) == 1:

            hc = matching_handler_classes[0]

            return Response.plain(
                inspect.getsource(hc))

class Scratch(Handler):

    route_strings = set(['GET /scratch'])

    route = Handler.check_route_strings

    def handle(self, req):

        return Response.tmpl('dashboard/scratch.html')

