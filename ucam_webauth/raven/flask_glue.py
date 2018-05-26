from __future__ import unicode_literals

import ucam_webauth.flask_glue
from . import Request, Response, RAVEN_LOGOUT

class AuthDecorator(ucam_webauth.flask_glue.AuthDecorator):
    """
    :class:`ucam_webauth.flask_glue.AuthDecorator`, configured for live Raven

    Refer to :mod:`ucam_webauth.flask_glue` for documentation.
    """

    #:
    request_class = Request
    #:
    response_class = Response
    #:
    logout_url = RAVEN_LOGOUT
