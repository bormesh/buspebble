# vim: set expandtab ts=4 sw=4 filetype=python:

import logging
import textwrap

from horsemeat.webapp import handler

from rtapebbletest.webapp.framework.response import Response

log = logging.getLogger(__name__)

module_template_prefix = 'framework'
module_template_package = 'rtapebbletest.webapp.framework.templates'

class Handler(handler.Handler):

    @property
    def four_zero_four_template(self):
        return 'framework_templates/404.html'

    def not_found(self, req):

        return super(Handler, self).not_found(req)

