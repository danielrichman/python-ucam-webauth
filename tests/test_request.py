from __future__ import unicode_literals

import sys
from nose.tools import assert_raises

if sys.version_info[0] >= 3:
    from urllib.parse import parse_qs
else:
    from urlparse import parse_qs

import ucam_webauth
import ucam_webauth.raven
import ucam_webauth.raven.demoserver

from ucam_webauth import Request, ATYPE_PWD, raven


class TestRequest(object):
    def test_url(self):
        request = str(Request(url="http://drichman.net/example"))
        assert request.lower() in \
                ('url=http%3a%2f%2fdrichman.net%2fexample&ver=3',
                 'ver=3&url=http%3a%2f%2fdrichman.net%2fexample')

        assert parse_qs(request) == \
                {"url": ["http://drichman.net/example"], "ver": ["3"]}

    def test_desc_msg(self):
        request = str(Request(url="http://drichman.net/example",
                              msg="simple message", desc="simple description"))
        assert parse_qs(request)["desc"] == ["simple description"]
        assert parse_qs(request)["msg"] == ["simple message"]

        for key in ("desc", "msg"):
            request = str(Request(url="http://drichman.net/example",
                                  **{key: "html <>& &amp; unicode \u0636"}))
            assert parse_qs(request)[key] == \
                    ["html <>&amp; &amp;amp; unicode &#1590;"]

            request = str(Request(url="http://drichman.net/example",
                                  encode_strings=False,
                                  **{key: "&manually; some & stuff"}))
            assert parse_qs(request)[key] == ["&manually; some & stuff"]

    def test_rejects_unprintable_desc_msg(self):
        for key in ("desc", "msg"):
            assert_raises(ValueError, Request,
                            url="http://drichman.net/example",
                            encode_strings=False, **{key: "asdf \x14 dfgh"})

    def test_rejects_empty_aauth(self):
        assert_raises(ValueError, Request, url="http://drichman.net/example",
                                           aauth=set())

    def test_aauth(self):
        request = str(Request(url="http://drichman.net/example",
                              aauth=set([ATYPE_PWD])))
        assert parse_qs(request)["aauth"] == ["pwd"]

        request = str(Request(url="http://drichman.net/example",
                              aauth=set(["hello", "world"])))
        assert parse_qs(request)["aauth"] in (["hello,world"], ["world,hello"])

    def test_iact(self):
        request = str(Request(url="http://drichman.net/example", iact=None))
        assert "iact" not in parse_qs(request)

        request = str(Request(url="http://drichman.net/example", iact=True))
        assert parse_qs(request)["iact"] == ["yes"]

        request = str(Request(url="http://drichman.net/example", iact=False))
        assert parse_qs(request)["iact"] == ["no"]

    def test_params(self):
        request = str(Request(url="http://drichman.net/example",
                              params="some & dfgh asdf"))
        assert parse_qs(request)["params"] == ["some & dfgh asdf"]

    def test_fail(self):
        request = str(Request(url="http://drichman.net/example", fail=True))
        assert parse_qs(request)["fail"] == ["yes"]

    def test_raven(self):
        request = str(raven.Request(url="http://drichman.net/example",
                                    desc="example",
                                    aauth=set([ATYPE_PWD]), fail=True))
        prefix = "https://raven.cam.ac.uk/auth/authenticate.html?"
        query = request[len(prefix):]
        assert request.startswith(prefix)
        assert parse_qs(query) == {
                "url": ["http://drichman.net/example"],
                "desc": ["example"],
                "aauth": ["pwd"],
                "fail": ["yes"],
                "ver": ["3"]
            }

    def test_raven_demoserver(self):
        request = str(raven.demoserver.Request(
                                url="http://drichman.net/example"))
        assert request.lower() in (
                "https://demo.raven.cam.ac.uk/auth/authenticate.html?"
                "url=http%3a%2f%2fdrichman.net%2fexample&ver=3",
                "https://demo.raven.cam.ac.uk/auth/authenticate.html?"
                "ver=3&url=http%3a%2f%2fdrichman.net%2fexample"
            )
