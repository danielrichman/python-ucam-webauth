"""
Raven Demo Server

Provides Request and Response subclasses (as in the raven module), except
these use the settings of the Raven Demo Server,
`<http://raven.cam.ac.uk/project/test-demo/>`_

.. data:: PUBKEY901

    The key used to verify responses, from
    `<https://raven.cam.ac.uk/project/keys/demo_server/>`_

.. data:: RAVEN_DEMO_AUTH

    The WLS' authentication start page:
    ``RAVEN_DEMO_AUTH.format(quoted_query_string)`` will produce a request

.. data:: RAVEN_DEMO_LOGOUT

    The WLS' logout page: redirecting to this URL will log the user out of
    Raven completely.

"""

from __future__ import unicode_literals

from . import _load_key

import ucam_webauth


__all__ = ["PUBKEY901", "RAVEN_DEMO_AUTH", "RAVEN_DEMO_LOGOUT",
           "Request", "Response"]


PUBKEY901 = _load_key("901")
RAVEN_DEMO_AUTH = "https://demo.raven.cam.ac.uk/auth/authenticate.html?{0}"
RAVEN_DEMO_LOGOUT = "https://demo.raven.cam.ac.uk/auth/logout.html"


class Request(ucam_webauth.Request):
    """
    :class:`ucam_webauth.Request`, configured for the Raven demo server

    Refer to :mod:`ucam_webauth` for documentation.

    .. method:: __str__

        Returns a full URL: the raven demoserver authentication url, with
        the query string set to contain the request data

    """

    def __str__(self):
        query_string = ucam_webauth.Request.__str__(self)
        return RAVEN_DEMO_AUTH.format(query_string)

class Response(ucam_webauth.Response):
    """
    :class:`ucam_webauth.Response`, configured for the Raven demo server

    Refer to :mod:`ucam_webauth` for documentation.

    .. attribute:: keys

        A single key; `kid` '901' maps to :data:`PUBKEY901`.

    """

    keys = {"901": PUBKEY901}
    #:
    old_version_ptags = frozenset(["current"])
