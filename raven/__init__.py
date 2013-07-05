# Copyright 2013 Daniel Richman
#
# This file is part of python-raven
#
# python-raven is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-raven is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with python-raven.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

"""
Raven

The Raven module subclasses ucam_webauth.Request and ucam_webauth.Response
in order to use the Raven URLs and the Raven response settings (default ptags,
signing keys) respectively.

Contains the Request and Response classes, and the RAVEN_LOGOUT constant
(the url to redirect to in order to log out).
"""

__name__ = "raven"
__version__ = "0.1"
__author__ = "Daniel Richman"
__copyright__ = "Copyright 2013 Daniel Richman"
__email__ = "main@danielrichman.co.uk"
__license__ = "LGPL3"


import os
import os.path
from M2Crypto.X509 import load_cert

import ucam_webauth

__all__ = ["PUBKEY2", "RAVEN_AUTH", "RAVEN_LOGOUT", "Request", "Response"]


def _load_key(kid):
    filename = os.path.join(os.path.dirname(__file__),
                            "keys/pubkey{0}.crt".format(kid))
    return load_cert(filename).get_pubkey().get_rsa()


PUBKEY2 = _load_key("2")
RAVEN_AUTH = "https://raven.cam.ac.uk/auth/authenticate.html?{0}"
RAVEN_LOGOUT = "https://raven.cam.ac.uk/auth/logout.html"


class Request(ucam_webauth.Request):
    """ucam_webauth.Request, configured for live Raven"""

    def __str__(self):
        query_string = ucam_webauth.Request.__str__(self)
        return RAVEN_AUTH.format(query_string)

class Response(ucam_webauth.Response):
    """ucam_webauth.Response, configured for live Raven"""

    old_version_ptags = set(["current"])
    keys = {"2": PUBKEY2}
