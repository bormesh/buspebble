# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf8:

import logging
import pprint

import clepy
from horsemeat.webapp import response

from rtapebbletest import fancyjsondumps

log = logging.getLogger(__name__)

class Response(response.Response):

    """
    Add stuff here that is specific to the rtapebbletest response.
    """

    # TODO: Move into horsemeat
    @classmethod
    def csv_file(cls, filelike, filename, FileWrap):

        """

        Here's an example usage::

            query = textwrap.dedent('''
                copy (
                    select *
                    from blah
                )
                to stdout with csv header
                ''')

            tf = tempfile.NamedTemporaryFile()

            cursor.copy_expert(query, tf)

            return Response.csv_file(filelike=tf,
                                     filename='csv-data',
                                     FileWrap=req.environ['wsgi.file_wrapper'])

        """

        block_size = 4096

        return cls(
            '200 OK',
            [('Content-Type', 'text/csv'),
             ('Content-Disposition', 'attachment; filename={0}'.format(filename))],
            FileWrap(filelike, block_size))

    # TODO: Move into horsemeat
    @property
    def body(self):
        return self._body


    # TODO: Move into horsemeat
    @body.setter
    def body(self, val):

        """
        If the body isn't wrapped in a list, I'll wrap it in a list.

        (Only if it's not a file wrapper)
        """

        from gunicorn.http.wsgi import FileWrapper

        if not isinstance(val, FileWrapper):
            self._body = clepy.listmofize(val)
        else:
            self._body = val


    @classmethod
    def json(cls, data):

        log.debug("about to return this data after JSON-encoding "
           "it:\n{0}\n".format(fancyjsondumps(data)))

        return super(Response, cls).json(data)


