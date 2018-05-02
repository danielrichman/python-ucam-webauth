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
