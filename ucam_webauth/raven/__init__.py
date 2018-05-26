"""
Raven

The Raven module subclasses :class:`ucam_webauth.Request` and
:class:`ucam_webauth.Response` in order to use the Raven URLs and the Raven
response settings (default ptags and signing keys).

.. data:: PUBKEY2

    The key used to verify responses, from
    `<https://raven.cam.ac.uk/project/keys/>`_

.. data:: RAVEN_AUTH

    The WLS' authentication start page:
    ``RAVEN_AUTH.format(quoted_query_string)`` will produce a request

.. data:: RAVEN_LOGOUT

    The WLS' logout page: redirecting to this URL will log the user out of
    Raven completely.

"""

from __future__ import unicode_literals

import os
import os.path

import ucam_webauth
import ucam_webauth.rsa


__all__ = ["PUBKEY2", "RAVEN_AUTH", "RAVEN_LOGOUT", "Request", "Response"]


def _load_key(kid):
    filename = os.path.join(os.path.dirname(__file__),
                            "keys/pubkey{0}".format(kid))
    with open(filename, 'rb') as f:
        return ucam_webauth.rsa.load_key(f.read())


PUBKEY2 = _load_key("2")
RAVEN_AUTH = "https://raven.cam.ac.uk/auth/authenticate.html?{0}"
RAVEN_LOGOUT = "https://raven.cam.ac.uk/auth/logout.html"


class Request(ucam_webauth.Request):
    """
    :class:`ucam_webauth.Request`, configured for live Raven

    Refer to :mod:`ucam_webauth` for documentation.

    .. method:: __str__

        Returns a full URL: the raven authentication url, with the query
        string set to contain the request data

    """

    def __str__(self):
        query_string = ucam_webauth.Request.__str__(self)
        return RAVEN_AUTH.format(query_string)

class Response(ucam_webauth.Response):
    """
    :class:`ucam_webauth.Response`, configured for live Raven

    Refer to :mod:`ucam_webauth` for documentation.

    .. attribute:: keys

        A single key; `kid` '2' maps to :data:`PUBKEY2`.

    """

    keys = {"2": PUBKEY2}
    #:
    old_version_ptags = frozenset(["current"])
