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

import logging
import functools
import urllib

from calendar import timegm
from time import time as time_float
time = lambda: int(time_float())

from flask import request, session, redirect, abort

logger = logging.getLogger("ucam_webauth.flask_glue")

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
      - require_ptags: (set of strings) require the ptags to contain _any_
        string in require_ptags (non empty intersection)

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
                    require_principal=None,
                    require_ptags=frozenset(["current"])):
        # TODO handle POST 

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

    def _prop_helper(self, name):
        return session.get("_ucam_webauth", {}).get(name, None)

    @property
    def principal(self):
        return self._prop_helper("principal")

    @property
    def ptags(self):
        ptags = self._prop_helper("ptags")
        if ptags is not None:
            ptags = frozenset(ptags)
        return ptags

    @property
    def issue(self):
        return self._prop_helper("issue")

    @property
    def life(self):
        return self._prop_helper("life")

    @property
    def last(self):
        return self._prop_helper("last")

    @property
    def expires(self):
        state = session.get("_ucam_webauth", {})
        if "principal" not in state:
            return None
        expires = self._get_expires(state)
        if len(expires) == 0:
            return None
        else:
            return min(when for reason, when in expires)

    @property
    def expires_all(self):
        state = session.get("_ucam_webauth", {})
        if "principal" not in state:
            return None
        return self._get_expires(state)

    def _wrapped(self, view_function, view_args):
        # we always modify the session. Changes to mutable objects (our
        # state dict) arn't automatically picked up
        session.modified = True

        if "WLS-Response" in request.args:
            if request.method != "GET":
                abort(405)
            if len(request.args.getlist("WLS-Response")) != 1:
                abort(400)

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

        ok, reason = self._check_expires(state)
        if not ok:
            logger.info("session expired (%s): redirecting to WLS", reason)
            return self._redirect_to_wls()

        if not self.check_authorised(state["principal"],
                                     frozenset(state["ptags"])):
            logger.info("not authorised: bad principal (%s) or ptags (%r)",
                        state["principal"], state["ptags"])
            abort(403)

        state["last"] = time()

        return view_function(**view_args)

    def _handle_response(self, response):
        url_without_response = self._check_url(response.url)
        if url_without_response is None:
            abort(400)

        if response.success:
            if not response.check_iact_aauth(self.iact, self.aauth):
                logger.warning("response.check_iact failed: "
                               "auth=%s sso=%s iact=%s aauth=%s",
                               response.auth, response.sso,
                               self.iact, self.aauth)
                abort(400)

            issue = timegm(response.issue.timetuple())
            if not self._check_issue(issue):
                abort(400)

            if not self._is_new_session(response):
                logger.debug("new session")
                self.session_new()

            session["_ucam_webauth"] = \
                    {"principal": response.principal,
                     "ptags": list(response.ptags),
                     "issue": issue, "life": response.life,
                     "last": time()}

        else:
            session["_ucam_webauth"] = {"response_failure": True}

        return redirect(url_without_response)

    def _check_url(self, wls_response_url):
        actual_url = request.url

        # note: mod_ucam_webauth simply strips everything up to a ?
        # from both urls and compares.

        # see waa2wls-protocol.txt - the WLS appends (?|&)WLS-Response=
        # so, removing that from the end of the string should recover
        # the exact url sent in the request
        start = max(actual_url.rfind("?WLS-Response="),
                    actual_url.rfind("&WLS-Response="))
        if start == -1:
            logger.warning("have args['WLS-Response'] but "
                           "(?|&)WLS-Response not in request.url?")
            return None

        # check that nothing funny is going on (that the dumb parsing done
        # above is correct)
        response_start = start + len(".WLS-Response=")
        response_part = urllib.unquote_plus(actual_url[response_start:])
        if response_part != request.args["WLS-Response"]:
            logger.debug("WLS-Response removal failed "
                         "(removed: %r, request.args: %r)",
                         response_part, request.args["WLS-Response"])
            return None

        # finally check that they agree.
        actual_url = actual_url[:start]
        if wls_response_url != actual_url:
            logger.debug("response.url did not match url visited "
                         "(replay of WLS-Response to other website?) "
                         "response.url=%r request.url=%r",
                         wls_response_url, actual_url)
            return None

        return wls_response_url

    def _check_issue(self, issue):
        now = time()
        lower = now - self.issue_bounds[0]
        upper = now + self.issue_bounds[1]
        result = lower <= issue <= upper
        if not result:
            logger.debug("response had bad issue: "
                         "now=%s issue=%s lower=%s upper=%s",
                         now, issue, lower, upper)
        return result

    def _is_new_session(self, response):
        state = session["_ucam_webauth"]
        if "principal" not in state:
            return False

        principal = state["principal"]
        ptags = frozenset(state["ptags"])
        return response.principal == principal and response.ptags == ptags

    def _redirect_to_wls(self):
        req = self.request_class(request.url, self.desc, self.aauth,
                                 self.iact, self.msg)
        return redirect(str(req))

    def _get_expires(self, state):
        expires = []

        if self.max_life is not None:
            expires.append(("config max life", state["issue"] + self.max_life))
        if self.use_wls_life and state["life"] is not None:
            expires.append(("wls life", state["issue"] + state["life"]))
        if self.inactive_timeout is not None:
            expires.append(("inactive", state["last"] + self.inactive_timeout))

        return expires

    def _check_expires(self, state):
        expires = self._get_expires(state)
        now = time()
        for reason, when in expires:
            if when < now:
                return False, reason
        else:
            return True, None

    def check_authorised(self, principal, ptags):
        if self.require_principal is not None:
            if principal not in self.require_principal:
                return False
            
        if self.require_ptags is not None:
            if self.require_ptags & ptags == set():
                return False

        return True

    def session_new(self):
        pass
