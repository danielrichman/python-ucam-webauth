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

import logging
import functools

from datetime import datetime, timedelta
from time import time as time_float
time = lambda: int(time_float())

from flask import request, session, redirect, url_for, abort

logger = logging.getLogger("ucam_webauth.flask")

class AuthDecorator(object):
    """
    An instance of this class decorates views to add authentication.

    To use it, you'll need to subclass it and set response_class and
    request_class (See raven.flask.AuthDecorator). Then,

        auth_decorator = AuthDecorator(your settings)

        @app.route("/some_url")
        @auth_decorator
        def my_view():
            return "You are " + auth_decorator.principal

    Note that since it uses flask.session, you'll need to set a secret_key.

    This tries to emulate the feel of applying mod_ucam_webauth to a file.

    The decorator wraps the view in a function that:

      - checks if there is a response from the WLS
          - checks if flask.session is empty - if so, then we deduce that the
            user has cookies disabled, and must abort immediately with
            403 Forbidden, or we will start a redirect loop
          - checks if the authentication method use is permitted by self.aauth
            and user-interaction respected self.iact; otherwise abort with
            400 Bad Request
          - updates the state with the response: updating the principal,
            ptags and issue information if it was a success, or 
            clearing them (but setting a flag - see below: 401 Authentication
            Required will be thrown after redirect) if it was a failure
          - redirects, to remove WLS-Response from query.args
      - checks if the "response was an authentication failure" flag is set in
        flask.session, clear the flag and abort with 401
      - checks to see if we are authenticated (and the session hasn't expired)
          - if not, sends the user to the WLS to authenticate
      - checks to see if the principal / ptags are permitted
          - if not, aborts with a 403 Forbidden
      - updates the 'last used' time in the state (to implement
        inactive_timeout)
      - calls the original view function

    You may wish to catch the 401 and 403 aborts with app.errorhandler.

    The principal, their ptags, the issue and life from the WLS are available
    as properties of the AuthDecorator.

    Settings:

      - desc, aauth, iact, msg: see ucam_webauth.Request
      - max_life: upper bound (in seconds; or None for no upper bound) on how
        long a successful authentication can last
      - use_wls_life: (bool) lower the life of the session to the life reported
        by the WLS, if it is lower than max_life
      - inactive_timeout: (integer; seconds or None for no timeout)
      - issue_bounds: (a tuple (lower, upper)) - how close the "issue"
        (datetime the WLS says the authentication happened at) must be to now
        (must have  now - lower < issue < now + upper
        this is a combination of two settings found in mod_ucam_webauth:
        clock skew and response timeout,
        issue_bounds=(clock_skew + response_time, clock_skew) is equivalent)
      - require_principal: (set of strings; None for no restriction) require
        the principal to be in the set
      - require_ptags: (set of strings) require the ptags to contain every
        string in require_ptags

    More complex customisation:

      - override check_authorised(principal, ptags) to do more complex
        checking than require_principal, require_ptags.
      - override session_new (see below)

    Logging out:

        call and return the value of auth_decorator.logout().

        The call will clear the session state, and logout() returns a redirect
        to the Raven logout page. Be aware of the fact the opportunity for
        replay attacks when using the default flask session handlers.

    Session expiration

        The AuthDecorator only touches session["_ucam_webauth"]. If you've
        saved other (important) things to the session object, you may want to
        clear them out when the state changes.

        You can do this by subclassing and overriding session_new. It is called
        whenever a response is received from the WLS, except if the response
        is successful re-authentication as the same prinicple and ptags
        after session expiry.

    """

    request_class = None
    response_class = None

    def __init__(self, desc=None, aauth=None, iact=None, msg=None,
                    max_life=7200, use_wls_life=False,
                    inactive_timeout=None, issue_bounds=(15,5),
                    require_principal=None, require_ptags=set(["current"])):
        self.desc = desc
        self.aauth = aauth
        self.iact = iact
        self.msg = msg
        self.max_life = max_life
        self.use_wls_life = use_wls_life
        self.inactive_timeout = inactive_timeout
        self.issue_bounds = issue_bounds
        self.require_principal = require_principal
        self.require_ptags = require_ptags

    def __call__(self, view_function):
        def wrapper(**view_args):
            return self._wrapped(view_function, view_args)
        functools.update_wrapper(wrapper, view_function)
        return wrapper

    @property
    def principal(self):
        return session.get("_ucam_webauth", {}).get("principal", None)

    @property
    def ptags(self):
        ptags = session.get("_ucam_webauth", {}).get("ptags", None)
        if ptags is not None:
            ptags = set(ptags)
        return ptags

    @property
    def issue(self):
        return session.get("_ucam_webauth", {}).get("issue", None)

    @property
    def life(self):
        return session.get("_ucam_webauth", {}).get("life", None)

    def _wrapped(self, view_function, view_args):
        if "WLS-Response" in request.args:
            if request.method != "GET":
                abort(405)
            if "_ucam_webauth" not in session:
                # we set this before redirecting - so the user has cookies
                # disabled. avoid a redirect loop
                abort(403)

            r = self.response_class(request.args["WLS-Response"])
            return self._handle_response(r)

        if "_ucam_webauth" not in session:
            session["_ucam_webauth"] = {}

        state = session["_ucam_webauth"]

        if state.get("response_failure", False):
            del state["response_failure"]
            abort(401)

        if "principal" not in state:
            logger.info("unauthenticated: redirecting to WLS")
            return self._redirect_to_wls()

        if not self._check_life(state):
            logger.info("session expired (life): redirecting to WLS")
            return self._redirect_to_wls()

        if not self._check_inactive(state):
            logger.info("session expired (inactivity): redirecting to WLS")
            return self._redirect_to_wls()

        if not self.check_authorised(state["principal"], set(state["ptags"])):
            logger.info("not authorised: bad principal (%s) or ptags (%r)",
                        state["principal"], state["ptags"])
            abort(403)

        state["last"] = time()

        return view_function(**view_args)

    def _handle_response(self, response):
        if response.success:
            if not response.check_iact_aauth(self.iact, self.aauth):
                logger.warning("response.check_iact failed: "
                               "auth=%s sso=%s iact=%s aauth=%s",
                               response.auth, response.sso,
                               self.iact, self.aauth)
                abort(400)

            if not self._check_issue(response):
                abort(400)

            if not self._is_reauth(response):
                logger.debug("new session")
                self.session_new()

            session["_ucam_webauth"] = \
                    {"principal": response.principal,
                     "ptags": list(response.ptags),
                     "issue": response.issue, "life": response.life,
                     "last": time()}

        else:
            session["_ucam_webauth"] = {"response_failure": True}

        new_args = request.args.copy()
        new_args.update(request.view_args)
        new_args.pop("WLS-Response")
        return redirect(url_for(request.endpoint, **new_args))

    def _check_issue(self, response):
        now = datetime.utcnow()
        lower = now - timedelta(seconds=self.issue_bounds[0])
        upper = now + timedelta(seconds=self.issue_bounds[1])
        return lower <= response.issue <= upper

    def _is_reauth(self, response):
        state = session["_ucam_webauth"]
        if "principal" not in state:
            return False

        principal = state["principal"]
        ptags = set(state["ptags"])
        return response.principal == principal and response.ptags == ptags

    def _redirect_to_wls(self):
        args = request.args.copy()
        args.update(request.view_args)
        url = url_for(request.endpoint, _external=True, **args)
        req = self.request_class(url, self.desc, self.aauth, self.iact,
                                 self.msg)
        return redirect(str(req))

    def _check_life(self, state):
        wls_life = state["life"] if self.use_wls_life else None

        if self.max_life is None:
            life = wls_life
        elif wls_life is None:
            life = self.max_life
        else:
            life = min(wls_life, self.max_life)

        if life is None:
            return True
        else:
            end = state["issue"] + timedelta(seconds=life)
            return end > datetime.utcnow()

    def _check_inactive(self, state):
        return (self.inactive_timeout is None) or \
                (self["last"] + self.inactive_timeout > time())

    def check_authorised(self, principal, ptags):
        if self.require_principal is not None:
            if principal not in self.require_principal:
                return False
            
        if self.require_ptags is not None:
            if not self.require_ptags <= ptags:
                return False

        return True

    def session_new(self):
        pass
