# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf8:

import functools
import json

from horsemeat import HorsemeatJSONEncoder

class rtapebbletestJSONEncoder(HorsemeatJSONEncoder):

    """
    Each project can modify this just for fun if they want.
    """
    pass


# TODO: add a docstring on this guy.
fancyjsondumps = functools.partial(
    json.dumps,
    cls=rtapebbletestJSONEncoder,
    sort_keys=True,
    indent=4,
    separators=(',', ': '))
