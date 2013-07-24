from __future__ import unicode_literals

import os.path
import string
import base64
import itertools
from datetime import datetime
from hashlib import sha1
from M2Crypto.RSA import gen_key, new_pub_key, load_key
from M2Crypto.util import quiet_genparam_callback

from nose.tools import assert_raises

import ucam_webauth
import raven
import raven.demoserver


_genkey = lambda: gen_key(1024, 65537, callback=quiet_genparam_callback)
example_keys = dict((kid, _genkey()) for kid in "abc")
_pubkey = lambda kid: new_pub_key(example_keys[kid].pub())
_pubkeys = lambda kids: dict((kid, _pubkey(kid)) for kid in kids)


class Response_NoVerify(ucam_webauth.Response):
    old_version_ptags = set()
    def _verify(self):
        self.signed = None

class Response_OldPtags(Response_NoVerify):
    old_version_ptags = set(["config1", "config2"])

class Response_KeysAB(ucam_webauth.Response):
    old_version_ptags = set()
    keys = _pubkeys("ab")

class Response_MoreATypes(Response_NoVerify):
    @classmethod
    def _atype_obj(cls, auth):
        return auth


class TestResponse(object):
    def respstr(self, ver=3, kid=None, sign_kid=None, sig=None, **kwargs):
        keys = ("status", "msg", "issue", "id", "url", "principal", "ptags",
                "auth", "sso", "life", "params")
        for key in keys:
            if key not in kwargs:
                kwargs[key] = ""

        if ver == 1 or ver == 2:
            fmt = "{ver}!{status}!{msg}!{issue}!{id}!{url}!{principal}!" \
                    "{auth}!{sso}!{life}!{params}"
        elif ver == 3:
            fmt = "3!{status}!{msg}!{issue}!{id}!{url}!{principal}!{ptags}!" \
                    "{auth}!{sso}!{life}!{params}"
        else:
            assert False

        digested_data = fmt.format(ver=ver, **kwargs)

        if (kid or sign_kid) and sig is None:
            key = example_keys[sign_kid or kid]
            sig = key.sign(sha1(digested_data).digest(), 'sha1')
            table = string.maketrans("+/=", "-._")
            sig = base64.b64encode(sig).translate(table)

        if kid is None:
            kid = ""
        if sig is None:
            sig = ""

        return digested_data + "!{kid}!{sig}".format(kid=kid, sig=sig)

    def test_parses_simple_success_string(self, rcls=None, **extra):
        string = self.respstr(status="200",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example",
                    principal="djr61", auth="pwd",
                    **extra)

        if rcls:
            response = rcls(string)
        else:
            response = Response_NoVerify(string)

        # don't check ver, ptags, kid, or sig so that other tests can use
        # **extra to test simple variants on this string

        assert response.status is ucam_webauth.STATUS_SUCCESS
        assert response.issue == datetime(2013, 7, 1, 10, 23, 45)
        assert response.id == "unique"
        assert response.url == "http://drichman.net/example"
        assert response.principal == "djr61"
        assert response.auth is ucam_webauth.ATYPE_PWD
        assert response.sso == set()
        assert response.life is None
        assert response.params == ""

        return response

    def test_demands_mandatory_fields_of_successful_string(self):
        base = dict(status="200",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example",
                    principal="djr61", auth="pwd")

        for key in set(base) - set("auth"):
            kwargs = base.copy()
            del kwargs[key]
            string = self.respstr(**kwargs)
            assert_raises(ValueError, Response_NoVerify, string)

    def test_parses_optional_fields(self, rcls=None, **extra):
        string = self.respstr(status="200", msg="message",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example", principal="djr61",
                    ptags="one,two", auth="pwd", sso="pwd", life="345",
                    params="somedata",
                    **extra)
        if rcls:
            response = rcls(string)
        else:
            response = Response_NoVerify(string)

        # don't check ver, ptags, kid, or sig so that other tests can use
        # **extra to test simple variants on this string

        assert response.status is ucam_webauth.STATUS_SUCCESS
        assert response.msg == "message"
        assert response.issue == datetime(2013, 7, 1, 10, 23, 45)
        assert response.id == "unique"
        assert response.url == "http://drichman.net/example"
        assert response.principal == "djr61"
        assert response.auth is ucam_webauth.ATYPE_PWD
        assert response.sso == set([ucam_webauth.ATYPE_PWD])
        assert list(response.sso)[0] is ucam_webauth.ATYPE_PWD
        assert response.life == 345
        assert response.params == "somedata"

        return response

    def test_parses_failed_string(self, rcls=None, **extra):
        string = self.respstr(status="410",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example",
                    **extra)
        if rcls:
            response = rcls(string)
        else:
            response = ucam_webauth.Response(string)

        # don't check kid, or sig so that other tests can use
        # **extra to test simple variants on this string

        assert response.status is ucam_webauth.STATUS_CANCELLED
        assert response.issue == datetime(2013, 7, 1, 10, 23, 45)
        assert response.id == "unique"
        assert response.url == "http://drichman.net/example"
        assert response.principal == response.ptags == response.auth == \
                response.sso == response.life == None
        assert response.params == ""

        return response

    def test_demands_mandatory_fields_of_failed_string(self):
        base = dict(status="410",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example")

        for key in base:
            kwargs = base.copy()
            del kwargs[key]
            string = self.respstr(**kwargs)
            assert_raises(ValueError, ucam_webauth.Response, string)

    def test_rejects_nonempty_successy_fields_on_failed_string(self):
        for key in ("principal", "ptags", "auth", "sso"):
            assert_raises(ValueError, self.test_parses_failed_string,
                    **{key: "pwd"})
            # use "pwd" to pass auth/sso parsing

    def test_parses_old_versions(self):
        assert self.test_parses_simple_success_string().ver == 3
        assert self.test_parses_optional_fields().ver == 3
        assert self.test_parses_optional_fields().ptags == set(["one", "two"])
        assert self.test_parses_failed_string().ver == 3

        assert self.test_parses_simple_success_string(ver=1).ver == 1
        assert self.test_parses_simple_success_string(ver=2).ver == 2
        assert self.test_parses_failed_string(ver=1).ver == 1
        assert self.test_parses_failed_string(ver=2).ver == 2

    def test_verifies_signature(self, **extra):
        kwargs = {"rcls": Response_KeysAB, "kid": "a"}
        kwargs.update(extra)
        assert self.test_parses_simple_success_string(**kwargs).signed is True
        assert self.test_parses_optional_fields(**kwargs).signed is True
        assert self.test_parses_failed_string(**kwargs).signed is True

        # Check it sets kid and signed correctly
        signed = self.test_parses_simple_success_string(**kwargs)
        mocked = self.test_parses_simple_success_string()
        unsigned = self.test_parses_failed_string()

        assert signed.kid == "a"
        assert mocked.kid is None and mocked.signed is None
        assert unsigned.kid is None and unsigned.signed is False

    def test_verifies_signature_old_versions(self):
        self.test_verifies_signature(ver=1)
        self.test_verifies_signature(ver=2)

    def test_demands_signature_on_success_string(self):
        assert_raises(ValueError, self.test_parses_simple_success_string,
                rcls=ucam_webauth.Response)

    def test_rejects_invalid_signature(self):
        # or "rejects signature with wrong key"
        assert_raises(ValueError, self.test_parses_simple_success_string,
                rcls=Response_KeysAB, kid="a", sign_kid="b")

    def test_rejects_signature_with_unlisted_key(self):
        assert_raises(ValueError, self.test_parses_simple_success_string,
                rcls=Response_KeysAB, kid="c", sign_kid="c")

    def test_rejects_signature_without_kid(self):
        assert_raises(ValueError, self.test_parses_simple_success_string,
                rcls=Response_KeysAB, sign_kid="a")

    def test_rejects_kid_without_signature(self):
        assert_raises(ValueError, self.test_parses_simple_success_string,
                rcls=Response_KeysAB, kid="a", sig="")

    def test_decodes_string_fields(self):
        string = self.respstr(status="200", msg="me%21ssa%25ge",
                    issue="20130701T102345Z", id="%21un%21iq%25ue",
                    url="http://dric%25hma%21n.net/example",
                    principal="djr%21%21%252561",
                    ptags="one,t%2521wo", auth="pwd", sso="pwd", life="345",
                    params="some%2520da%2521%21ta")
        response = Response_NoVerify(string)

        assert response.msg == "me!ssa%ge"
        assert response.id == "!un!iq%ue"
        assert response.url == "http://dric%hma!n.net/example"
        assert response.principal == "djr!!%2561"
        assert response.ptags == set(["one", "t%21wo"])
        assert response.params == "some%20da%21!ta"

    def test_rejects_bad_string_encoding(self):
        string = self.respstr(status="200",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example%20",
                    principal="djr61", auth="pwd")
        assert_raises(ValueError, Response_NoVerify, string)

    def test_rejects_bad_base64(self):
        string = self.respstr(status="200",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example",
                    principal="djr61", auth="pwd",
                    kid="a", sig="~~ not base 64")

        # parsing of the b64 is done in _parse_base_types
        assert_raises(ValueError, Response_NoVerify, string)

    def test_rejects_bad_status(self):
        for bad in ("", "900", "asdf"):
            string = self.respstr(status=bad,
                        issue="20130701T102345Z", id="unique",
                        url="http://drichman.net/example",
                        principal="djr61", auth="pwd")
            assert_raises(ValueError, Response_NoVerify, string)

    def test_rejects_bad_atype(self):
        for bad in ("", "invalid", "PWD"):
            string = self.respstr(status="200",
                        issue="20130701T102345Z", id="unique",
                        url="http://drichman.net/example",
                        principal="djr61", auth=bad)
            assert_raises(ValueError, Response_NoVerify, string)

            string = self.respstr(status="200",
                        issue="20130701T102345Z", id="unique",
                        url="http://drichman.net/example",
                        principal="djr61", sso=bad)
            assert_raises(ValueError, Response_NoVerify, string)

    def test_auth_sso_combinations(self):
        for auth, sso in (("", "pwd"), ("pwd", "pwd"), ("pwd", "")):
            string = self.respstr(status="200",
                        issue="20130701T102345Z", id="unique",
                        url="http://drichman.net/example",
                        principal="djr61", auth=auth, sso=sso)
            Response_NoVerify(string) # doesn't rase an error

        string = self.respstr(status="200",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example",
                    principal="djr61", auth="", sso="")

        assert_raises(ValueError, Response_NoVerify, string)

    def test_uses_old_ptags(self):
        self.test_parses_simple_success_string().ptags == set([])

        response = self.test_parses_simple_success_string(
                        ver=1, rcls=Response_OldPtags)
        assert response.ptags == set(["config1", "config2"])

    def test_future_atypes(self):
        string = self.respstr(status="200",
                    issue="20130701T102345Z", id="unique",
                    url="http://drichman.net/example",
                    principal="djr61", auth="wand", sso="tst,trumpet")
        response = Response_MoreATypes(string)
        assert response.auth == "wand"
        assert response.sso == set(["tst", "trumpet"])

    def test_check_iact_aauth(self):
        auth = ("", "pwd", "tst")
        sso = ("", "pwd", "tst", "pwd,tst")
        iact = (True, False, None)
        aauth = (None, set(["pwd"]))

        cases = list(itertools.product(auth, sso, iact, aauth))

        # aauth = None,  pwd    None,  pwd    None,  pwd
        # iact =  True          False         None          # auth, sso
        expect = (None,  None,  None,  None,  None,  None,  # "", ""
                  False, False, True,  True,  True,  True,  # "", "pwd"
                  False, False, True,  False, True,  False, # "", "tst"
                  False, False, True,  True,  True,  True,  # "", "pwd,tst"

                  True,  True,  False, False, True,  True,  # "pwd", ""
                  True,  True,  False, False, True,  True,  # "pwd", "pwd"
                  True,  True,  False, False, True,  True,  # "pwd", "tst"
                  True,  True,  False, False, True,  True,  # "pwd", "pwd,tst"

                  True,  False, False, False, True,  False, # "tst", ""
                  True,  False, False, False, True,  True,  # "tst", "pwd"
                  True,  False, False, False, True,  False, # "tst", "tst"
                  True,  False, False, False, True,  True)  # "tst", "pwd,tst"

        for (c_auth, c_sso, c_iact, c_aauth), c_expect in zip(cases, expect):
            string = self.respstr(status="200",
                        issue="20130701T102345Z", id="unique",
                        url="http://drichman.net/example",
                        principal="djr61", auth=c_auth, sso=c_sso)

            if c_expect is None:
                assert_raises(ValueError, Response_MoreATypes, string)
            else:
                response = Response_MoreATypes(string)
                result = response.check_iact_aauth(c_iact, c_aauth)
                m = "failed: auth={0} sso={1} iact={2} aauth={3} expect={4}" \
                        .format(c_auth, c_sso, c_iact, c_aauth, c_expect)
                assert result is c_expect, m

    def test_raven_demoserver(self):
        response = raven.demoserver.Response(
            "3!200!!20130704T122413Z!1372940650-10196-2!https://demo.ra"
            "ven.cam.ac.uk/nonexistant!test0001!current!!pwd!35873!!901"
            "!m9S7JSnLZ2.ZoZc1t8Bn4wAfV1LtMhjPwl0eeunAWBPmXLWmhlgFrrS69"
            "GLFYkxXSUBjbuq42QZlktRRbb5KKAmB8mRfWWHG3q6-P0H8kjrWloFMWSM"
            "H3mGsmpbeqhakHwhsOW5NjZpiIaFsFNPsEr8Tv5NWoCFC0DCtkJLZzAg_")

        assert response.ver == 3
        assert response.status == ucam_webauth.STATUS_SUCCESS
        assert response.msg is None
        assert response.issue == datetime(2013, 7, 4, 12, 24, 13)
        assert response.id == "1372940650-10196-2"
        assert response.url == "https://demo.raven.cam.ac.uk/nonexistant"
        assert response.principal == "test0001"
        assert response.ptags == set(["current"])
        assert response.auth is None
        assert response.sso == set([ucam_webauth.ATYPE_PWD])
        assert response.life == 35873
        assert response.params == ""
        assert response.kid == "901"
        assert response.signed == True

        response = raven.demoserver.Response(
            "1!200!!20130704T123040Z!1372941040-10342-2!https://demo.ra"
            "ven.cam.ac.uk/nonexistant!test0040!pwd!!36000!!901!ZWbAXob"
            "YyHZ82hie6yiTMl06xHv-31VMutXWYMyuAQWDdG3R7PlVCWsy6iU9Z1LxP"
            "kuSkjOEnalVUjbg64EOGl8B22EefUQYysWIUqMKYLrOgsiB8I4kVqqc8sj"
            "NLFsC7.b-fZRzCVKdmLfG725tHEEtkZKorxIHW2AM9xLJyMk_")

        assert response.ver == 1
        assert response.status == ucam_webauth.STATUS_SUCCESS
        assert response.msg is None
        assert response.issue == datetime(2013, 7, 4, 12, 30, 40)
        assert response.id == "1372941040-10342-2"
        assert response.url == "https://demo.raven.cam.ac.uk/nonexistant"
        assert response.principal == "test0040"
        assert response.auth is ucam_webauth.ATYPE_PWD
        assert response.sso == set()
        assert response.life == 36000
        assert response.params == ""
        assert response.kid == "901"
        assert response.signed == True

        response = raven.demoserver.Response(
            "1!410!!20130704T122941Z!1372940981-10144-16!https://demo.ra"
            "ven.cam.ac.uk/nonexistant!!!!!!901!Dudyo.Nq-2Spz.nhLhdOO.aQ"
            "VNWnfoL2k2xvXLFsyh2ovKJvmMFe2MKbQ4vI1NRasl4LlFNyaY46Tzjf.kT"
            "q9I45IcSZ1yWTLlQLHycQmg9AjjmkFCfVHKgnaCEe0quJY2l2SLCT1HMtDk"
            "odYGnrRWaPLvzRAUvbVWUjJqpMPT0_")

        assert response.ver == 1
        assert response.status == ucam_webauth.STATUS_CANCELLED
        assert response.msg == None
        assert response.issue == datetime(2013, 7, 4, 12, 29, 41)
        assert response.id == "1372940981-10144-16"
        assert response.url == "https://demo.raven.cam.ac.uk/nonexistant"
        assert response.principal == response.auth == \
                response.sso == response.life == None
        assert response.params == ""
        assert response.kid == "901"
        assert response.signed == True
