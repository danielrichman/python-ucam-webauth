from __future__ import unicode_literals

import sys
import base64
import time
import functools
import random
import json
from datetime import datetime

if sys.version_info[0] >= 3:
    from urllib.parse import urlencode, parse_qs
else:
    from urllib import urlencode
    from urlparse import parse_qs

from nose.tools import assert_raises

from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import Unauthorized
import flask
import flask.sessions
import ucam_webauth
import ucam_webauth.flask_glue

class FakeTime(object):
    def __init__(self):
        self.value = int(time.time())

    def __call__(self):
        return self.value

    def advance(self, amount):
        self.value += amount

class FakeRequest(ucam_webauth.Request):
    def __str__(self):
        query_string = ucam_webauth.Request.__str__(self)
        return "/fake_wls?" + query_string

class FakeOS(object):
    def set_urandom(self, v):
        self._urandom = base64.b64decode(v)

    def __init__(self):
        self.set_urandom("aaaa")

    def urandom(self, amt):
        return self._urandom

# Rather than write something that generates the WLS response format....
def make_response(**kwargs):
    now = ucam_webauth.flask_glue.time()

    # id is probably not guaranteed unique but close enough
    values = dict(ver=3, status=ucam_webauth.STATUS_SUCCESS,
                  url="http://localhost/decorated",
                  issue=now, signed=True, ptags=set(["current"]),
                  auth="pwd", sso=set(), life=86400, kid="A",
                  params="aaaa")
    values.update(kwargs)

    for k in ("sso", "ptags"):
        if values[k] is not None:
            values[k] = list(str(x) for x in values[k])

    values["status"] = int(values["status"])

    if isinstance(values["issue"], int):
        values["issue"] = datetime.utcfromtimestamp(values["issue"])
    values["issue"] = list(values["issue"].timetuple()[:6])

    if "success" not in values:
        values["success"] = (values["status"] == ucam_webauth.STATUS_SUCCESS)

    return urlencode((("WLS-Response", json.dumps(values)), ))

class FakeResponse(ucam_webauth.Response):
    def __init__(self, string):
        kwargs = json.loads(string)
        self.__dict__.update(kwargs)
        if self.sso is not None:
            self.sso = set(self.sso)
        self.status = ucam_webauth.STATUS_CODES[self.status]
        self.issue = datetime(*self.issue)

class AuthDecorator(ucam_webauth.flask_glue.AuthDecorator):
    request_class = FakeRequest
    response_class = FakeResponse
    logout_url = "http://localhost/wls_logout"

class WLS(object):
    def __init__(self):
        self._expect = []

    def expect(self, request, response):
        request = MultiDict(request)
        if "url" not in request:
            request["url"] = "http://localhost/decorated"
        if "ver" not in request:
            request["ver"] = "3"
        if not request["url"].startswith("http"):
            request["url"] = "http://localhost/"
        if "params" not in request:
            request["params"] = "aaaa"
        self._expect.append((request, response))

    def check(self):
        assert self._expect == []

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type is None:
            self.check()

    def __call__(self):
        # a view function
        assert self._expect != []
        request, response = self._expect.pop()
        args = flask.request.args
        assert request == args
        goto = args["url"]
        if goto.endswith("?"):
            pass
        elif "?" in goto:
            goto += "&"
        else:
            goto += "?"
        goto += response
        return flask.redirect(goto)

class TestRig(object):
    def __init__(self, cls=AuthDecorator, *args, **kwargs):
        self.wls = WLS()

        self.app = flask.Flask("test_auth_decorator")
        self.app.testing = True
        self.app.secret_key = str(random.random())

        kwargs.setdefault("can_trust_request_host", True)

        self.authdecorator = cls(*args, **kwargs)
        view = self.authdecorator(self.decorated)

        self.app.add_url_rule('/fake_wls', 'wls', self.wls)
        self.app.add_url_rule('/decorated', 'decorated', view)
        self.app.add_url_rule('/decorated/<view_arg>', 'decorated', view)
        self.app.add_url_rule('/logout', 'logout', self.authdecorator.logout)

        self.client = self.app.test_client()
        self.active = False
        self._expect_view = []

    def decorated(self, view_arg=None):
        assert self._expect_view != []
        args = flask.request.args
        expect = self._expect_view.pop(0)
        assert (flask.request.url, view_arg, args) == expect
        return "Hello World"

    def expect_view(self, url="http://localhost/decorated",
                          view_arg=None, args={}):
        self._expect_view.append((url, view_arg, MultiDict(args)))

    def session_transaction(self):
        return self.client.session_transaction()

    def __enter__(self):
        assert not self.active
        assert self._expect_view == []
        self.active = True
        class V(object):
            expect = self.expect_view
        return self.client.__enter__(), self.wls.__enter__(), V()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        try:
            assert self.active
            self.active = False

            assert self._expect_view == []
        except:
            if exc_type is None:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                raise
        finally:
            try:
                self.client.__exit__(exc_type, exc_value, exc_traceback)
            except:
                if exc_type is None:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    raise
            finally:
                self.wls.__exit__(exc_type, exc_value, exc_traceback)

class TestAuthDecorator(object):
    def setup(self):
        self.old_ucam_webauth_time = ucam_webauth.flask_glue.time
        self.old_ucam_webauth_os = ucam_webauth.flask_glue.os
        self.time = FakeTime()
        self.os = FakeOS()
        ucam_webauth.flask_glue.time = self.time
        ucam_webauth.flask_glue.os = self.os

    def teardown(self):
        ucam_webauth.flask_glue.time = self.old_ucam_webauth_time

    def check_auth(self, rig, **kwargs):
        with rig as (client, wls, views):
            kwargs.setdefault("principal", "djr61")
            wls.expect({}, make_response(**kwargs))
            views.expect()

            response = client.get("/decorated", follow_redirects=True)
            assert response.status_code == 200
            assert response.data == b"Hello World"

    def check_remembered_auth(self, rig):
        with rig as (client, wls, views):
            views.expect()

            response = client.get("/decorated")
            assert response.status_code == 200
            assert response.data == b"Hello World"

    def check_auth_abort(self, rig, code, **kwargs):
        with rig as (client, wls, views):
            kwargs.setdefault("principal", "djr61")
            wls.expect({}, make_response(**kwargs))

            response = client.get("/decorated", follow_redirects=True)
            assert response.status_code == code

    def test_authenticates_new(self):
        self.check_auth(TestRig())

    def test_authenticated_properties(self):
        rig = TestRig(max_life=500)

        self.check_auth(rig, ptags=set(["current", "dfgh", "lkjf"]), life=213)
        issue = self.time()
        self.time.advance(5)

        with rig as (client, wls, views):
            views.expect()
            assert client.get("/decorated").status_code == 200

            d = rig.authdecorator
            assert d.principal == "djr61"
            assert d.ptags == set(["current", "dfgh", "lkjf"])
            assert d.issue == issue
            assert d.life == 213
            assert d.last == self.time()
            # expires and expires_all are checked in the expires tests

        self.time.advance(600)

        # reauth due to expiry: diff attrs from WLS; should change
        self.check_auth(rig, principal="other",
                        ptags=set(["current", "blah", "lkjf"]), life=642)
        issue = self.time()
        self.time.advance(20)

        with rig as (client, wls, views):
            views.expect()
            assert client.get("/decorated").status_code == 200

            d = rig.authdecorator
            assert d.principal == "other"
            assert d.ptags == set(["current", "blah", "lkjf"])
            assert d.issue == issue
            assert d.life == 642
            assert d.last == self.time()

        # expire and cancel
        self.time.advance(600)

        with rig as (client, wls, views):
            wls.expect({}, make_response(status=ucam_webauth.STATUS_CANCELLED))
            r = client.get("/decorated", follow_redirects=True)
            assert r.status_code == 401

            assert d.principal is None
            assert d.ptags is None
            assert d.issue is None
            assert d.life is None
            assert d.last is None
            assert d.expires is None
            assert d.expires_all is None

    def test_remembers_authentication(self):
        rig = TestRig()

        self.check_auth(rig)
        self.check_remembered_auth(rig)

    def test_tests_cookies(self):
        rig = TestRig()

        with rig as (client, wls, views):
            r = client.get("/decorated")
            assert r.status_code == 303
            url, query = r.headers["location"].split("?")

        with rig.session_transaction() as session:
            del session["_ucam_webauth"]

        with rig as (client, wls, views):
            wls.expect({}, make_response(principal="djr61"))

            # the decorator should assume the user has cookies disabled
            # and bail to avoid a redirect loop
            r = client.get(url, query_string=query, follow_redirects=True)
            assert r.status_code == 403

    def check_remembered_and_expires_props(self, rig, expires, expires_all):
        with rig as (client, wls, views):
            views.expect()
            assert client.get("/decorated").status_code == 200
            actual_expires = rig.authdecorator.expires
            assert actual_expires == expires
            actual_expires_all = rig.authdecorator.expires_all
            assert actual_expires_all == expires_all

    def test_expires_none(self):
        rig = TestRig(max_life=None, use_wls_life=False, inactive_timeout=None)

        self.check_auth(rig)
        self.check_remembered_and_expires_props(rig, None, [])
        self.time.advance(1000000)
        self.check_remembered_and_expires_props(rig, None, [])

    def test_expires_max_life(self):
        rig = TestRig(max_life=7200, use_wls_life=False, inactive_timeout=None)

        self.check_auth(rig)
        when = self.time() + 7200
        self.check_remembered_and_expires_props(rig, when,
                [("config max life", when)])
        self.time.advance(7199)
        self.check_remembered_auth(rig)
        self.time.advance(2)
        # should reauth
        self.check_auth(rig)

    def test_expires_use_wls_life(self):
        for life in [460, 8000, 10]:
            rig = TestRig(max_life=None, use_wls_life=True,
                          inactive_timeout=None)
            self.check_auth(rig, life=life)
            when = self.time() + life
            self.check_remembered_and_expires_props(rig, when,
                    [("wls life", when)])
            self.time.advance(life - 1)
            self.check_remembered_auth(rig)
            self.time.advance(2)
            self.check_auth(rig)

    def test_expires_inactive(self):
        rig = TestRig(max_life=None, use_wls_life=False, inactive_timeout=3600)

        self.check_auth(rig)
        for i in range(10):
            self.time.advance(3599)
            when = self.time() + 3600
            self.check_remembered_and_expires_props(rig, when,
                    [("inactive", when)])
        self.time.advance(3601)
        self.check_auth(rig)

    def test_expires_combinations_wls_life(self):
        rig = TestRig(max_life=3600, use_wls_life=True, inactive_timeout=300)

        # inactive < wls life < max life. Test expires: wls life
        self.check_auth(rig, life=600)
        self.check_remembered_and_expires_props(rig, self.time() + 300,
                [("config max life", self.time() + 3600),
                 ("wls life", self.time() + 600),
                 ("inactive", self.time() + 300)])
        self.time.advance(250)
        self.check_remembered_auth(rig)
        self.time.advance(250)
        self.check_remembered_and_expires_props(rig, self.time() + 100,
                [("config max life", self.time() + 3100),
                 ("wls life", self.time() + 100),
                 ("inactive", self.time() + 300)])
        self.time.advance(250)
        self.check_auth(rig) # reauth

    def test_expires_combinations_max_life(self):
        rig = TestRig(max_life=600, use_wls_life=True, inactive_timeout=300)

        # inactive < max life < wls life. Test expires: max life
        self.check_auth(rig, life=1000)
        self.check_remembered_and_expires_props(rig, self.time() + 300,
                [("config max life", self.time() + 600),
                 ("wls life", self.time() + 1000),
                 ("inactive", self.time() + 300)])
        self.time.advance(250)
        self.check_remembered_auth(rig)
        self.time.advance(250)
        self.check_remembered_and_expires_props(rig, self.time() + 100,
                [("config max life", self.time() + 100),
                 ("wls life", self.time() + 500),
                 ("inactive", self.time() + 300)])
        self.time.advance(250)
        self.check_auth(rig) # reauth

    def test_expires_combinations_inactive(self):
        rig = TestRig(max_life=600, use_wls_life=True, inactive_timeout=300)

        # inactive < max life < wls life: Test expires: inactive
        self.check_auth(rig, life=7200)
        self.time.advance(301)
        self.check_auth(rig) # reauth

    def test_expires_combinations_wls_life_omitted(self):
        # case 1: wls life enabled but not provided by WLS
        # case 2: wls disabled but provided by WLS

        for enable, provide in ((True, None), (False, 100)):
            rig = TestRig(max_life=600, use_wls_life=enable,
                          inactive_timeout=300)

            # Test expires: inactive
            self.time.advance(301)
            self.check_auth(rig, life=provide)

            # Test expires: max life
            self.time.advance(250)
            self.check_remembered_and_expires_props(rig, self.time() + 300,
                    [("config max life", self.time() + 350),
                     ("inactive", self.time() + 300)])
            self.time.advance(250)
            self.check_remembered_auth(rig)
            self.time.advance(250)
            self.check_auth(rig)

    def test_auth_request_options(self):
        rig = TestRig(desc="Description", msg="Pls Auth",
                      aauth=set(["banana"]), iact=True)
        with rig as (client, wls, views):
            wls.expect({"desc": "Description", "msg": "Pls Auth",
                        "aauth": "banana", "iact": "yes"},
                       make_response(principal="djr61", auth="banana"))
            views.expect()

            response = client.get("/decorated", follow_redirects=True)
            assert response.status_code == 200
            assert response.data == b"Hello World"

    def test_sets_session_modified(self):
        O = flask.sessions.SecureCookieSessionInterface
        class S(O):
            def save_session(self, app, session, response):
                if flask.request.endpoint != "wls":
                    assert session.modified
                return O.save_session(self, app, session, response)

        rig = TestRig()
        rig.app.session_interface = S()

        self.check_auth(rig)

        for i in range(10):
            self.check_remembered_auth(rig)
            if i % 2 == 0:
                self.time.advance(1)

    def test_removes_wls_response_from_URL(self):
        rig = TestRig()

        with rig as (client, wls, views):
            r = client.get("/decorated")
            assert r.status_code == 303
            url, query = r.headers["location"].split("?")

        with rig as (client, wls, views):
            wls.expect({}, make_response(principal="djr61"))

            r = client.get(url, query_string=query)
            assert r.status_code == 302
            url, query = r.headers["location"].split("?")
            assert url == "http://localhost/decorated"
            assert "WLS-Response" in query

        with rig as (client, wls, views):
            r = client.get("/decorated", query_string=query)
            assert r.status_code == 303
            assert r.headers["location"] == "http://localhost/decorated"

        with rig as (client, wls, views):
            views.expect()
            r = client.get("/decorated")
            assert r.status_code == 200

    def test_removes_wls_response_from_URL_401(self):
        rig = TestRig()

        with rig as (client, wls, views):
            r = client.get("/decorated")
            assert r.status_code == 303
            url, query = r.headers["location"].split("?")

        with rig as (client, wls, views):
            wls.expect({}, make_response(status=ucam_webauth.STATUS_CANCELLED))

            r = client.get(url, query_string=query)
            assert r.status_code == 302
            url, query = r.headers["location"].split("?")
            assert url == "http://localhost/decorated"
            assert "WLS-Response" in query

        with rig as (client, wls, views):
            r = client.get("/decorated", query_string=query)
            assert r.status_code == 303
            assert r.headers["location"] == "http://localhost/decorated"

        with rig as (client, wls, views):
            r = client.get("/decorated")
            assert r.status_code == 401

    # Sadly, the real world raven still uses version 1 for negative responses
    def test_handles_v1_removing_query_parameters(self):
        rig = TestRig()

        with rig as (client, wls, views):
            r = client.get("/decorated?special")
            assert r.status_code == 303
            url, query = r.headers["location"].split("?")

        with rig as (client, wls, views):
            u = "http://localhost/decorated?special"
            status = ucam_webauth.STATUS_CANCELLED
            wls.expect({"url": u}, make_response(ver=1, status=status, url=u))

            r = client.get(url, query_string=query)
            assert r.status_code == 302
            url, query = r.headers["location"].split("?")
            assert url == "http://localhost/decorated"

        # with a v1 response, the WLS actually deletes other query parameters
        assert query.startswith("special&WLS-Response")
        query = query[len("special&"):]

        with rig as (client, wls, views):
            r = client.get("/decorated", query_string=query)
            assert r.status_code == 303
            # it should restore the query parameter:
            assert r.headers["location"] == "http://localhost/decorated?special"

        with rig as (client, wls, views):
            # and finally give us a 401
            r = client.get("/decorated?special")
            assert r.status_code == 401

    def test_require_default(self):
        self.check_auth(TestRig(), principal="something",
                        ptags=set(["current"]))
        self.check_auth(TestRig(), principal="anything",
                        ptags=set(["current", "another"]))
        self.check_auth_abort(TestRig(), 403, principal="anything",
                              ptags=set(["not_current"]))

    def test_require_principal(self):
        make_rig = lambda: TestRig(require_principal=set(["djr61", "test2"]))

        self.check_auth(make_rig())
        self.check_auth(make_rig(), principal="test2")
        self.check_auth_abort(make_rig(), 403, principal="other")

        # should still have default ptags settings
        self.check_auth_abort(make_rig(), 403, ptags=set())

    def test_require_ptags(self):
        make_rig = lambda: TestRig(require_ptags=set(["tag1", "tag2"]))

        self.check_auth(make_rig(), ptags=set(["tag1"]))
        self.check_auth(make_rig(), ptags=set(["tag2", "current"]))
        self.check_auth_abort(make_rig(), 403, ptags=set(["current"]))
        self.check_auth_abort(make_rig(), 403, ptags=set())

        make_rig = lambda: TestRig(require_ptags=None)

        self.check_auth(make_rig(), ptags=set(["tag1"]))
        self.check_auth(make_rig(), ptags=set())

    def test_require_combo(self):
        options = {"require_principal": set(["djr61", "test1", "test2"]),
                   "require_ptags": set(["current", "testtag"])}
        should_auth = (("djr61", set(["current"])),
                       ("djr61", set(["current", "testtag", "extra"])),
                       ("test1", set(["testtag"])),
                       ("test2", set(["current", "testtag", "extra"])))
        should_reject = (("test9", set(["current", "testtag", "extra"])),
                         ("test9", set(["current"])),
                         ("djr61", set(["other"])),
                         ("test1", set()))

        for principal, ptags in should_auth:
            rig = TestRig(**options)
            self.check_auth(rig, principal=principal, ptags=ptags)

        for principal, ptags in should_reject:
            rig = TestRig(**options)
            self.check_auth_abort(rig, 403, principal=principal, ptags=ptags)

    def test_custom_check_auth(self):
        class MyAuthDecorator(AuthDecorator):
            def __init__(self, *args, **kwargs):
                AuthDecorator.__init__(self, *args, **kwargs)
                self._expect_check = []

            def check_authorised(self, principal, ptags):
                assert self._expect_check != []
                e_principal, e_ptags, result = self._expect_check.pop(0)
                assert e_principal == principal
                assert e_ptags == ptags
                return result

            def expect(self, principal="djr61", ptags=set(["current"]),
                             result=True):
                self._expect_check.append((principal, ptags, result))

            def __enter__(self):
                assert self._expect_check == []
                return self

            def __exit__(self, exc_type, exc_value, exc_traceback):
                if exc_type is None:
                    assert self._expect_check == []

        rig = TestRig(cls=MyAuthDecorator)
        with rig.authdecorator as checks:
            checks.expect(result=True)
            self.check_auth(rig)

        rig = TestRig(cls=MyAuthDecorator)
        with rig.authdecorator as checks:
            checks.expect("tst", set(["tag1", "tag2"]), True)
            self.check_auth(rig, principal="tst", ptags=set(["tag1", "tag2"]))

        rig = TestRig(cls=MyAuthDecorator)
        with rig.authdecorator as checks:
            checks.expect(result=False)
            self.check_auth_abort(rig, 403)

    def test_issue_bounds(self):
        cases = ((-16, False), (-14, True), (-1, True),
                 (1, True), (4, True), (6, False))
        for issue_adj, expect_ok in cases:
            rig = TestRig(issue_bounds=(15, 5))
            issue = self.time() + issue_adj
            if expect_ok:
                self.check_auth(rig, issue=issue)
            else:
                self.check_auth_abort(rig, 400, issue=issue)

        rig = TestRig(issue_bounds=(0, 0))
        self.check_auth_abort(rig, 400, issue=self.time() - 1)
        self.check_auth_abort(rig, 400, issue=self.time() + 1)
        self.check_auth(rig)

    def test_checks_url(self):
        rig = TestRig()
        # Modify response.url: it should cause a mis-match
        self.check_auth_abort(rig, 400, url="http://localhost/other")
        self.check_auth_abort(rig, 400, url="http://other/decorated")
        self.check_auth_abort(rig, 400, url="http://localhost/decorated?test")

        rig = TestRig()

        with rig as (client, wls, views):
            # keep the response url as before, but modify the request url so
            # that they do not match
            url = "http://localhost/decorated?special"
            wls.expect({"url": url}, make_response(principal="djr61"))

            response = client.get("/decorated?special", follow_redirects=True)
            assert response.status_code == 400

    def test_doesnt_nuke_session(self):
        rig = TestRig()

        with rig.session_transaction() as session:
            session["some_other_data"] = True

        self.check_auth(rig)

        with rig.session_transaction() as session:
            assert session["some_other_data"] == True
            assert set(session.keys()) == \
                    set(["_ucam_webauth", "some_other_data"])
            session["more_data"] = 5

        self.time.advance(10)
        self.check_remembered_auth(rig)

        with rig.session_transaction() as session:
            assert session["more_data"] == 5

    def test_session_new(self):
        class MyAuthDecorator(AuthDecorator):
            def __init__(self, *args, **kwargs):
                AuthDecorator.__init__(self, *args, **kwargs)
                self._expect_session_new = 0

            def session_new(self):
                assert self._expect_session_new != 0
                self._expect_session_new -= 1
                flask.session["call"] = flask.session.get("call", 0) + 1

            def expect(self):
                self._expect_session_new += 1

            def __enter__(self):
                assert self._expect_session_new == 0
                return self

            def __exit__(self, exc_type, exc_value, exc_traceback):
                if exc_type is None:
                    assert self._expect_session_new == 0

        rig = TestRig(cls=MyAuthDecorator, inactive_timeout=100,
                      require_ptags=None)

        with rig.authdecorator as session_new:
            session_new.expect()
            self.check_auth(rig)

        with rig.session_transaction() as session:
            assert session["call"] == 1

        with rig.authdecorator as session_new:
            self.check_remembered_auth(rig)
            self.time.advance(5)
            self.check_remembered_auth(rig)

        self.time.advance(101)

        with rig.authdecorator as session_new:
            session_new.expect()
            # expired, reauthed, principal changed
            self.check_auth(rig, principal="other")

        with rig.authdecorator as session_new:
            self.check_remembered_auth(rig)

        self.time.advance(101)

        with rig.authdecorator as session_new:
            session_new.expect()
            # expired, reauthed, ptags changed
            self.check_auth(rig, principal="other", ptags=set(["other"]))

        with rig.authdecorator as session_new:
            self.check_remembered_auth(rig)

        with rig.session_transaction() as session:
            assert session["call"] == 3

    def test_nice_wrapper(self):
        # check that 'url_for' works properly
        rig = TestRig()
        with rig as (client, wls, views):
            client.get("/decorated")
            assert flask.url_for('decorated', view_arg=5) == "/decorated/5"
            assert flask.request.endpoint == 'decorated'

    def test_view_arg(self):
        with TestRig() as (client, wls, views):
            u = "http://localhost/decorated/test"
            wls.expect({"url": u}, make_response(principal="djr61", url=u))
            views.expect(u, "test")
            r = client.get("/decorated/test", follow_redirects=True)
            assert r.status_code == 200

    def test_request_args(self):
        with TestRig() as (client, wls, views):
            u = "http://localhost/decorated?tst=12&tst=4&tst=0"
            wls.expect({"url": u}, make_response(principal="djr61", url=u))
            views.expect(u, None, [("tst", "12"), ("tst", "4"), ("tst", "0")])
            r = client.get("/decorated?tst=12&tst=4&tst=0",
                           follow_redirects=True)
            assert r.status_code == 200

    def test_checks_iact_aauth(self):
        class ExpectTracker(object):
            def __init__(self):
                self._expect = []

            def check(self, iact, aauth):
                assert self._expect != []
                e_iact, e_aauth, result = self._expect.pop(0)
                assert iact == e_iact and e_aauth == aauth
                return result

            def expect(self, iact, aauth, result):
                self._expect.append((iact, aauth, result))

            def __enter__(self):
                assert self._expect == []
                return self

            def __exit__(self, exc_type, exc_value, exc_traceback):
                if exc_type is None:
                    assert self._expect == []

        class TrackedResponse(FakeResponse):
            expect_tracker = ExpectTracker()

            def check_iact_aauth(self, iact, aauth):
                return self.expect_tracker.check(iact, aauth)

        class MyAuthDecorator(AuthDecorator):
            response_class = TrackedResponse

        et = TrackedResponse.expect_tracker
        rig = TestRig(cls=MyAuthDecorator)

        with et as checks:
            checks.expect(None, None, True)
            self.check_auth(rig)

        rig = TestRig(cls=MyAuthDecorator, iact=False, aauth=set(["test"]))

        with rig as (client, wls, views), et as checks:
            wls.expect({"iact": "no", "aauth": "test"},
                       make_response(principal="djr61"))
            checks.expect(False, set(["test"]), True)
            views.expect()

            r = client.get("/decorated", follow_redirects=True)
            assert r.status_code == 200

        rig = TestRig(cls=MyAuthDecorator, iact=True,
                      aauth=set([ucam_webauth.ATYPE_PWD]))

        with rig as (client, wls, views), et as checks:
            wls.expect({"iact": "yes", "aauth": "pwd"},
                       make_response(principal="djr61"))
            checks.expect(True, set(["pwd"]), False)

            r = client.get("/decorated", follow_redirects=True)
            assert r.status_code == 400

    def test_logout(self):
        rig = TestRig()
        self.check_auth(rig)

        with rig.session_transaction() as session:
            assert session["_ucam_webauth"]["state"] != {}

        with rig as (client, wls, views):
            r = client.get("/logout")
            assert r.status_code == 303
            assert r.headers["location"] == "http://localhost/wls_logout"

        with rig.session_transaction() as session:
            assert session["_ucam_webauth"] == {"params_token": "aaaa"}

        self.check_auth(rig)

    def test_before_request(self):
        # Though technically the other tests are testing the decorator
        # interface, since that's just a thin wrapper around calling
        # before_request(), it's already tested. This test just checks
        # that if you want to call the before_request() method directly,
        # you can, and that it behaves sensibly. It's modeled on
        # test_removes_wls_response_from_URL

        rig = TestRig()
        before_request = rig.authdecorator.before_request

        with rig.app.test_request_context("/before_request_test"):
            r = before_request()
            assert r.status_code == 303
            url, query = r.location.split("?")
            assert url == "/fake_wls"
            assert parse_qs(query) == \
                {"url": ["http://localhost/before_request_test"],
                 "ver": ["3"], "params": ["aaaa"]}
            session_save = flask.session.copy()

        # answer 1
        answer = "/before_request_test?" + \
                make_response(status=ucam_webauth.STATUS_CANCELLED,
                              url="http://localhost/before_request_test")

        with rig.app.test_request_context(answer):
            flask.session.update(session_save)
            r = before_request()
            assert r.status_code == 303
            assert r.location == "http://localhost/before_request_test"
            session_save_401 = flask.session.copy()

        with rig.app.test_request_context("/before_request_test"):
            flask.session.update(session_save_401)
            assert_raises(Unauthorized, before_request)

        # answer 2
        answer = "/before_request_test?" + \
                make_response(principal="djr61",
                              url="http://localhost/before_request_test")

        with rig.app.test_request_context(answer):
            flask.session.update(session_save)
            r = before_request()
            assert r.status_code == 303
            assert r.location == "http://localhost/before_request_test"
            session_save_200 = flask.session.copy()

        with rig.app.test_request_context("/before_request_test"):
            flask.session.update(session_save_200)
            r = before_request()
            assert r == None

    def test_random_params(self):
        rig = TestRig()
        self.os.set_urandom("bbbbaaaa")

        with rig as (client, wls, views):
            wls.expect({"params": "bbbbaaaa"},
                       make_response(principal="djr61", params="bbbbaaaa"))
            views.expect()

            response = client.get("/decorated", follow_redirects=True)
            assert response.status_code == 200
            assert response.data == b"Hello World"

    def test_checks_params(self):
        rig = TestRig()

        with rig as (client, wls, views):
            wls.expect({"params": "aaaa"},
                       make_response(principal="djr61", params="dddd"))

            response = client.get("/decorated", follow_redirects=True)
            assert response.status_code == 400

    def test_params_token_doesnt_break_multiple_auths(self):
        with TestRig() as (client, wls, views):
            wls.expect({"params": "cccc"},
                       make_response(principal="djr61", params="cccc"))
            views.expect()

            # Start authenticating...
            self.os.set_urandom("cccc")
            redir = client.get("/decorated")
            assert redir.status_code == 303 
            _, query = redir.location.split("?")
            assert parse_qs(query)["params"] == ["cccc"]
            # ... but don't follow through yet ...

            # Start a second auth...
            self.os.set_urandom("dddd")
            redir2 = client.get("/decorated")
            assert redir2.status_code == 303
            # ... but abandon it ...

            # ... now pick the first auth back up again and complete it
            # https://github.com/mitsuhiko/flask/issues/968
            url = redir.location[len("http://localhost"):]
            response = client.get(url, follow_redirects=True)
            assert response.status_code == 200

        with TestRig() as (client, wls, views):
            wls.expect({"params": "eeee"},
                       make_response(principal="djr61", params="eeee"))
            views.expect()

            # as above, but now follow the second auth to completion instead
            self.os.set_urandom("eeee")
            redir = client.get("/decorated")
            assert redir.status_code == 303 
            _, query = redir.location.split("?")
            assert parse_qs(query)["params"] == ["eeee"]

            self.os.set_urandom("ffff")
            response = client.get("/decorated", follow_redirects=True)
            assert response.status_code == 200

    def test_trusted_hosts(self):
        self.check_auth(TestRig())

        rig = TestRig(can_trust_request_host=False)
        class R(flask.Request):
            trusted_hosts = {'localhost'}
        rig.app.request_class = R
        self.check_auth(rig)

        rig = TestRig(can_trust_request_host=False)
        with rig as (client, wls, views):
            wls.expect({}, make_response(principal='djr61'))

            assert_raises(RuntimeError,
                          client.get, "/decorated", follow_redirects=True)

    # Check that the v1 branch doesn't break anything.
    # I'm tempted to say that a ver=1 successful response should be rejected, but
    # I'm not sure.
    def test_auth_v1(self):
        self.check_auth(TestRig(), ver=1)
