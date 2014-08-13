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

"""This module provides glue to make using python-raven with Flask easy"""

from __future__ import unicode_literals

import sys
import logging
import functools

if sys.version_info[0] >= 3:
    from urllib.parse import unquote_plus
else:
    from urllib import unquote_plus

from calendar import timegm
from time import time as time_float
time = lambda: int(time_float())

from flask import request, session, redirect, abort

logger = logging.getLogger("ucam_webauth.flask_glue")

class AuthDecorator(object):
    """
    An instance of this class decorates views to add authentication.

    To use it, you'll need to subclass it and set response_class,
    request_class and logout_url (see :class:`raven.flask_glue.AuthDecorator`).
    Then::

        auth_decorator = AuthDecorator() # settings, e.g., desc="..." go here

        @app.route("/some_url")
        @auth_decorator
        def my_view():
            return "You are " + auth_decorator.principal

    Or to require users be authenticated for all views::

        app.before_request(auth_decorator.before_request)

    Note that since it uses flask.session, you'll need to set
    :attr:`app.secret_key`.

    This tries to emulate the feel of applying mod_ucam_webauth to a file.

    The decorator wraps the view in a function that calls
    :meth:`before_request` first, calling the original view function if it
    does not return a redirect or abort.

    You may wish to catch the 401 and 403 aborts with :attr:`app.errorhandler`.

    The :attr:`principal`, their :attr:`ptags`, the :attr:`issue` and
    :attr:`life` from the WLS are available as attributes of the
    :class:`AuthDecorator` object
    (magic properties that retrieve the current values from ``flask.session``).
    Further, the attributes :attr:`expires` and :attr:`expires_all` give
    information on when the ucam_webauth session will expire.

    For the `desc`, `aauth`, `iact`, `msg` parameters, see
    :class:`ucam_webauth.Request`.

    Note that the `max_life`, `use_wls_life` and `inactive_timeout` parameters
    deal with the ucam_webauth session `only`; they only affect
    ``flask.session["_ucam_webauth"]``. Flask's session expiry, cookie
    lifetimes, etc. are independent.

    :type max_life: :class:`int` (seconds) or ``None``
    :param max_life: upper bound on how long a successful authentication can
                     last before it expires and the user must reauthenticate
    :type use_wls_life: :class:`bool`
    :param use_wls_life: should we lower the life of the session to the life
                         reported by the WLS, if it is less than `max_life`?
    :type inactive_timeout: :class:`int` (seconds) or ``None``
    :param inactive_timeout: expire the session if no request is processed
                             via this decorator in `inactive_timeout` seconds
    :type issue_bounds: :class:`tuple`: (:class:`int`, :class:`int`) (seconds)
    :param issue_bounds: a tuple, (lower, upper) - how close the `issue`
                         (datetime that the WLS says the authentication
                         happened at) must be to `now`
                         (i.e., require ``now - lower < issue < now + upper``;
                         this is a combination of two settings found in
                         mod_ucam_webauth: `clock skew` and `response timeout`,
                         ``issue_bounds=(clock_skew + response_timeout,
                         clock_skew)`` is equivalent)
    :type require_principal: :class:`set` of :class:`str`, or ``None``
    :param require_principal: require the principal to be in the set
    :type require_ptags: :class:`set` of :class:`str`, or ``None``
    :param require_ptags: require the ptags to contain `any` string in
                          `require_ptags` (i.e., non empty intersection)

    More complex customisation is possible:

    * override :meth:`check_authorised` to do more complex
      checking than `require_principal`, `require_ptags`
      (note that this replaces checking `require_principal`, `require_ptags`)

    * override :meth:`session_new`

      The :class:`AuthDecorator` only touches
      ``flask.session["_ucam_webauth"]``.
      If you've saved other (important) things to the session object, you
      may want to clear them out when the state changes.

      You can do this by subclassing and overriding session_new. It is called
      whenever a response is received from the WLS, except if the response
      is a successful re-authentication after session expiry, with the same
      `principal` and `ptags` as before.

    To log the user out, call :meth:`logout`, which will clear the session
    state. Further, :meth:`logout` returns a :meth:`flask.redirect` to the
    Raven logout page. Be aware that the default flask session handlers are
    susceptibleto replay attacks.

    POST requests:
    Since it will redirect to the WLS and back, the auth decorator will
    discard any POST data in the process. You may wish to either work
    around this (by subclassing and saving it somewhere before redirecting)
    or ensure that when it returns (with a GET request) to the URL, a
    sensible page is displayed (the form, or an error message).

    .. automethod:: __call__

    """

    request_class = None
    response_class = None
    logout_url = None

    def __init__(self, desc=None, aauth=None, iact=None, msg=None,
                    max_life=7200, use_wls_life=False,
                    inactive_timeout=None, issue_bounds=(15,5),
                    require_principal=None,
                    require_ptags=frozenset(["current"])):
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
        """
        Wraps `view_function` with the auth decorator

        (:class:`AuthDecorator` objects are callable so that they can be used
        as function decorators.)

        Calling it returns a 'wrapper' view function that calls
        :meth:`request` first.
        """

        def wrapper(**view_args):
            r = self.before_request()
            if r is not None:
                return r
            return view_function(**view_args)

        functools.update_wrapper(wrapper, view_function)
        return wrapper

    def _prop_helper(self, name):
        return session.get("_ucam_webauth", {}).get(name, None)

    @property
    def principal(self):
        """The current principal, or ``None``"""
        return self._prop_helper("principal")

    @property
    def ptags(self):
        """The current ptags, or ``None``"""
        ptags = self._prop_helper("ptags")
        if ptags is not None:
            ptags = frozenset(ptags)
        return ptags

    @property
    def issue(self):
        """
        When the last WLS response was issued

        `issue` is converted to a unix timestamp (:class:`int`), rather than
        the :class:`datetime` object used by :class:`ucam_webauth.Response`.
        (`issue` is ``None`` if there is no current session.)
        """
        return self._prop_helper("issue")

    @property
    def life(self):
        """life of the last WLS response (:class:`int` seconds), or ``None``"""
        return self._prop_helper("life")

    @property
    def last(self):
        """Time (:class:`int` unix timestamp) of the last decorated request"""
        return self._prop_helper("last")

    @property
    def expires(self):
        """When (:class:`int` unix timestamp) the current auth. will expire"""
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
        """
        A list of all things that could cause the current auth. to expire

        A list of (:class:`str`, :class:`int` unix timestamp) tuples;
        (`reason`, `when`).

        `reason` will be one of "config max life", "wls life" or "inactive".
        """

        state = session.get("_ucam_webauth", {})
        if "principal" not in state:
            return None
        return self._get_expires(state)

    def logout(self):
        """Clear the auth., and return a redirect to the WLS' logout page"""
        if "_ucam_webauth" in session:
            session.modified = True
            del session["_ucam_webauth"]
        return redirect(self.logout_url, code=303)

    def _wrapped(self, view_function, view_args):
        """Decorated functions are replaced with this function"""

    def before_request(self):
        """
        The "main" method

        * checks if there is a response from the WLS

          * checks if the current URL matches that which the WLS said it
            redirected to (avoid an evil admin of another site replaying
            successful authentications)
          * checks if ``flask.session`` is empty - if so, then we deduce that
            the user has cookies disabled, and must abort immediately with
            403 Forbidden, or we will start a redirect loop
          * checks if the authentication method used is permitted by `aauth`
            and user-interaction respected `iact` - if not, abort with
            400 Bad Request
          * updates the state with the response: updating the `principal`,
            `ptags` and `issue` information if it was a success, or
            clearing them (but setting a flag - see below: 401 Authentication
            Required will be thrown after redirect) if it was a failure
          * returns a redirect that removes ``WLS-Response`` from
            ``request.args``

        * checks if the "response was an authentication failure" flag is set
          in ``flask.session`` - if so, clears the flag and aborts with
          401 Authentication Required

        * checks to see if we are authenticated (and the session hasn't
          expired)

          * if not, returns a redirect that will sends the user to the
            WLS to authenticate

        * checks to see if the `principal` / `ptags` are permitted

          * if not, aborts with a 403 Forbidden

        * updates the 'last used' time in the state (to implement
          `inactive_timeout`)

        Returns ``None``, if the request should proceed to the actual
        view function.
        """

        # we always modify the session. Changes to mutable objects (our
        # state dict) aren't automatically picked up
        session.modified = True

        if "WLS-Response" in request.args:
            if request.method != "GET":
                abort(405)
            if hasattr(request.args, "getlist") and \
                    len(request.args.getlist("WLS-Response")) != 1:
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

        return None

    def _handle_response(self, response):
        """
        Deal with a response in the query string of this request

        * checks `url`, `iact`, `aauth` and `issue`
        * starts a new session if necessary (see :meth:`session_new`)
        * sets the 'auth failed' flag if necessary
        * redirects to remove ``WLS-Response`` from the url/query string

        """

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

        return redirect(url_without_response, code=303)

    def _check_url(self, wls_response_url):
        """
        Check if the response from the WLS was intended for us

        Checks that the current requested url (``flask.request.url``) matches
        the URL in the WLS' response, which is equal to the URL specified
        in the request to the WLS and is the URL to which the client was
        redirected after authentication.

        This is necessary to avoid an evil administrator of another website
        capturing and replaying successful authentications to his website to
        us.
        """

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
        response_part = unquote_plus(actual_url[response_start:])
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
        """Check that `issue` (from a response) is in an acceptable range"""

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
        """Is this a new session, or reauthentication (after expiry)?"""

        state = session["_ucam_webauth"]
        if "principal" not in state:
            return False

        principal = state["principal"]
        ptags = frozenset(state["ptags"])
        return response.principal == principal and response.ptags == ptags

    def _redirect_to_wls(self):
        """Create a request and return a redirect to the WLS"""
        req = self.request_class(request.url, self.desc, self.aauth,
                                 self.iact, self.msg)
        return redirect(str(req), code=303)

    def _get_expires(self, state):
        """Get a list of (reason, when) tuples describing expiration times"""
        expires = []

        if self.max_life is not None:
            expires.append(("config max life", state["issue"] + self.max_life))
        if self.use_wls_life and state["life"] is not None:
            expires.append(("wls life", state["issue"] + state["life"]))
        if self.inactive_timeout is not None:
            expires.append(("inactive", state["last"] + self.inactive_timeout))

        return expires

    def _check_expires(self, state):
        """Check whether the current authentication has expired"""
        expires = self._get_expires(state)
        now = time()
        for reason, when in expires:
            if when < now:
                return False, reason
        else:
            return True, None

    def check_authorised(self, principal, ptags):
        """
        Check if an authenticated user is authorised.

        The default implementation requires the principal to be in
        the whitelist :attr:`require_principal` (if it is not ``None``, in
        which case any principal is allowed) and the intersection of
        :attr:`require_ptags` and `ptags` to be non-empty (unless
        :attr:`require_ptags` is ``None``, in which case any ptags
        (or no `ptags` at all) is permitted).

        Note that the default value of :attr:`require_ptags` in
        :class:`raven.flask_glue.AuthDecorator` is ``{"current"}``.
        """

        if self.require_principal is not None:
            if principal not in self.require_principal:
                return False

        if self.require_ptags is not None:
            if self.require_ptags & ptags == set():
                return False

        return True

    def session_new(self):
        """
        Called when a new user authenticates

        More specifically, when :attr:`principal` or :attr:`ptags` changes.
        """
        pass
