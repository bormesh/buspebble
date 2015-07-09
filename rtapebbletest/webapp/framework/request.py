# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf8:

import logging

from horsemeat.webapp import request

log = logging.getLogger(__name__)

class Request(request.Request):

    def get_binder_id(self):

        if 'binder_id' in self:
            return self['binder_id']

        if 'binder_id' in self.wz_req.args:
            self['binder_id'] = int(self.wz_req.args['binder_id'])
            return self['binder_id']

        elif 'binder_id' in self.wz_req.form:
            self['binder_id'] = int(self.wz_req.form['binder_id'])
            return self['binder_id']

        elif self.global_session_data \
        and 'binder_id' in self.global_session_data:
            self['binder_id'] = self.global_session_data['binder_id']
            return self['binder_id']

        else:
            raise ValueError('Sorry, could not figure out binder ID')

    @property
    def client_IP_address(self):

        if 'HTTP_X_FORWARDED_FOR' in self:
            return self['HTTP_X_FORWARDED_FOR'].strip()

        elif 'REMOTE_ADDR' in self:
            return self['REMOTE_ADDR'].strip()

    @property
    def is_JSON(self):
        return 'json' in self.CONTENT_TYPE.lower()
