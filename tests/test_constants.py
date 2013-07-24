import ucam_webauth

class TestStatus(object):
    def test_attributes(self):
        const = ucam_webauth.Status(123, "fake", "example description")
        assert const.code == 123
        assert const.name == "fake"
        assert const.description == "example description"

    def test_equality(self):
        a = ucam_webauth.Status(123, "fake", "example description")
        b = ucam_webauth.Status(123, "other", "different description")
        c = ucam_webauth.Status(456, "fake", "example description")
        assert a == b
        assert a == 123 and 123 == a
        assert a != c and c != a
        assert a != 456 and 456 != a

    def test_int(self):
        const = ucam_webauth.Status(123, "fake", "example description")
        assert int(const) == 123

    def test_constants(self):
        assert ucam_webauth.STATUS_SUCCESS == 200
        assert ucam_webauth.STATUS_CANCELLED == 410
        assert ucam_webauth.STATUS_NOATYPES == 510
        assert ucam_webauth.STATUS_UNSUPPORTED_VERSION == 520
        assert ucam_webauth.STATUS_BAD_REQUEST == 530
        assert ucam_webauth.STATUS_INTERACTION_REQUIRED == 540
        assert ucam_webauth.STATUS_WAA_NOT_AUTHORISED == 560
        assert ucam_webauth.STATUS_AUTHENTICATION_DECLINED == 570

class TestAuthenticationType(object):
    def test_attributes(self):
        const = ucam_webauth.AuthenticationType("test", "some description")
        assert const.name == "test"
        assert const.description == "some description"

    def test_equality(self):
        a = ucam_webauth.AuthenticationType("test", "some description")
        b = ucam_webauth.AuthenticationType("test", "different description")
        c = ucam_webauth.AuthenticationType("other", "some description")
        assert a == b
        assert a == "test" and "test" == a
        assert a != c and c != a
        assert a != "other" and "other" != a

    def test_str(self):
        const = ucam_webauth.AuthenticationType("test", "some description")
        assert str(const) == "test"

    def test_constants(self):
        assert ucam_webauth.ATYPE_PWD == "pwd"
