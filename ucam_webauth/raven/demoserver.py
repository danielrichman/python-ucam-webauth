# Copyright 2013 Daniel Richman
#
# This file is part of python-ucam-webauth
#
# python-ucam-webauth is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ucam-webauth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with python-ucam-webauth.  If not, see <http://www.gnu.org/licenses/>.

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
