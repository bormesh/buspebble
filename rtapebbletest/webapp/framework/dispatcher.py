# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf-8:
# -*- coding: utf-8 -*-

import logging

from horsemeat.webapp import dispatcher

from rtapebbletest.webapp.framework import request

log = logging.getLogger(__name__)

class Dispatcher(dispatcher.Dispatcher):

    request_class = request.Request

    def make_handlers(self):

        log.info('Making rtapebbletest handlers...')

        self.handlers.extend(self.make_handlers_from_module_string(
            'rtapebbletest.webapp.mockups.handlers'))

        self.handlers.extend(self.make_handlers_from_module_string(
            'rtapebbletest.webapp.dashboard.handlers'))

        self.handlers.extend(self.make_handlers_from_module_string(
            'rtapebbletest.webapp.rtapebbletest.handlers'))

        self.handlers.extend(self.make_handlers_from_module_string(
            'rtapebbletest.webapp.notfound.handlers'))

    @property
    def error_page(self):

        log.debug("Getting error template...")

        j = self.cw.get_jinja2_environment()

        t = j.get_template('rtapebbletest/error.html')

        return t

