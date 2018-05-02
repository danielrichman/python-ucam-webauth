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
The ucam_webauth module implements version 3 of the WAA to WLS protocol.

It is not set up to talk to a specific WAA (i.e., Raven), and subclassing
this modules' classes is required to make it functional. In particular, you
probably want to use :mod:`ucam_webauth.raven`.

The protocol is implemented as defined at
`<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>`_
at the time of writing (though that URL may have since been replaced with a
newer version). A copy of wawa2wls-protocol.txt is included with python-raven,
and more information can be found at `<https://raven.cam.ac.uk/project/>`_.

.. glossary::

    WAA
        A WAA is a "Web Application Agent"
        (i.e., an application using this module)

    WLS
        The "Web Login Service" (i.e., Raven)

.. data:: ATYPE_PWD
          STATUS_SUCCESS
          STATUS_CANCELLED
          STATUS_NOATYPES
          STATUS_UNSUPPORTED_VERSION
          STATUS_BAD_REQUEST
          STATUS_INTERACTION_REQUIRED
          STATUS_WAA_NOT_AUTHORISED
          STATUS_AUTHENTICATION_DECLINED

    :class:`AuthenticationType` and :class:`Status` instances used as constants
    in requests and responses

    They compare equal with their corresponding integers (for status codes)
    and strings (for atypes).

.. data:: STATUS_CODES

    A dict mapping status.code (i.e., the integer status code) to the relevant
    status object

"""

from __future__ import unicode_literals

__name__ = "ucam_webauth"
__version__ = "0.9.0"
__author__ = "Daniel Richman"
__copyright__ = "Copyright 2013 Daniel Richman"
__email__ = "main@danielrichman.co.uk"
__license__ = "LGPL3"


import sys
import re
from datetime import datetime
from hashlib import sha1

if sys.version_info[0] >= 3:
    from base64 import b64decode
    maketrans = bytes.maketrans
    from urllib.parse import unquote, urlencode
else:
    from string import maketrans
    from urllib import unquote, urlencode
    import base64

    def b64decode(value, validate):
        result = base64.b64decode(value)
        if validate and base64.b64encode(result) != value:
            raise ValueError("Non-base64 digit found")
        return result


__all__ = ["Status", "STATUS_CODE_LIST", "STATUS_CODES",
           "AuthenticationType", "ATYPE_PWD", "Request", "Response"]


class AuthenticationType(object):
    """
    An Authentication Type

    This class exists to create the :const:`ucam_webauth.AUTH_PWD` constant.

    .. attribute:: name

        the name by which Ucam-webauth knows it

    .. attribute:: description

        a sentence describing it

    Note that comparing an :class:`AuthenticationType` object with a
    :class:`str` (or another :class:`AuthenticationType` object) will compare
    the :attr:`name` attribute only. Further, ``str(atype) == atype.name``.
    """

    def __init__(self, name, description):
        self.name = name
        self.description = description
    def __str__(self):
        return self.name
    def __repr__(self):
        return "<ucam_webauth.AuthenticationType {0}>".format(self.name)
    def __hash__(self):
        return hash(self.name)
    def __eq__(self, other):
        if isinstance(other, AuthenticationType):
            return self.name == other.name
        else:
            return self.name == other
    def __ne__(self, other):
        return not self == other

ATYPE_PWD = AuthenticationType("pwd", "Username and password")


class Status(object):
    """
    A WLS response Status

    .. attribute:: code

        a (three digit) integer

    .. attribute:: name

        short name for the status

    .. attribute:: description

        description: a sentence describing the status

    Note that comparing a :class:`Status` object with an integer
    (or another :class:`Status` object) will compare the :attr:`code`
    attribute only. Further, `int(status_object) == status_object.code`
    """

    def __init__(self, code, name, description):
        self.code = code
        self.name = name
        self.description = description
    def __int__(self):
        return self.code
    def __str__(self):
        return self.name
    def __repr__(self):
        return "<ucam_webauth.Status {0} {1}>".format(self.code, self.name)
    def __hash__(self):
        return hash(self.code)
    def __eq__(self, other):
        if isinstance(other, Status):
            return self.code == other.code
        elif isinstance(other, int):
            return self.code == other
        else:
            return False
    def __ne__(self, other):
        return not self == other

STATUS_CODE_LIST = (
    Status(200, "success", "Successful authentication."),
    Status(410, "cancelled", "The user cancelled the authentication request"),
    Status(510, "noatypes",
        "No mutually acceptable authentication types available"),
    Status(520, "unsupported_version", "Unsupported protocol version"),
    Status(530, "bad_request", "General request parameter error"),
    Status(540, "interaction_required", "Interaction would be required"),
    Status(560, "waa_not_authorised", "Interaction would be required"),
    Status(570, "authentication_declined",
        "The WLS declines to provide authentication services on this occasion")
)

STATUS_CODES = {}
for status_code in STATUS_CODE_LIST:
    STATUS_CODES[status_code.code] = status_code
    g_name = "STATUS_{0}".format(status_code.name.upper())
    globals()[g_name] = status_code
    __all__.append(g_name)
del status_code, g_name


class Request(object):
    """
    A Request to the WLS

    :type url: :class:`str`
    :param url: a fully qualified URL; the user will be returned here
                (along with the Response as a query parameter) afterwards
    :type desc: :class:`str`
    :param desc: optional description of the resource/website
                 (encoding - see below)
    :type aauth: :class:`set` of :class:`AuthenticationType` objects
    :param aauth: optional set of permissible authentication types;
                  we require the user to use one of them
                  (if empty, the WLS uses its default set)
    :type iact: ``True``, ``False`` or ``None``
    :param iact: interaction required, forbidden or don't care (respectively)
    :type msg: :class:`str`
    :param msg: optional message explaining why authentication is required
                (encoding - see below)
    :type params: :class:`str`
    :param params: data, which is returned unaltered in the :class:`Response`
    :type fail: :class:`bool`
    :param fail: if True, and authentication fails, the WLS must show an error
                 message and not redirect back to the WAA

    All parameters are available as attributes as of Request object,
    once created.

    .. attribute:: iact

    * :const:`True`: the user must re-authenticate
    * :const:`False`: no interaction with the user is permitted
      (the request will only succeed if the user's identity can be
      returned without interacting at all)
    * :const:`None` (default): interacts if required

    .. attribute:: msg
                   desc

        The 'msg' and 'desc' parameters are restricted to printable ASCII
        characters (0x20 - 0x7e). The WLS will convert '<' and '>' to '&lt;'
        and '&gt;' before using either string in HTML, preventing the
        inclusion of markup. However, it does not touch '&', so HTML character
        and numeric entities may be used to represent other characters.

        If `encode_strings` is ``True``, ``&`` will be escaped to ``&amp;``,
        and non-ascii characters in `msg` and `desc` will be converted to
        their numeric entities.

        Otherwise, it is up to you to encode your strings. An error will be
        raised if `msg` or `desc` contain non-printable-ASCII characters.

    .. attribute:: params

        The ucam-webauth protocol does not specify any restrictions on the
        content of params. However, awful things may happen if you put
        arbitrary binary data in here. The Raven server appears to interpret
        non-ascii contents as latin-1, turn them into html entities in order
        to put them in a hidden HTML input element, then turn them back into
        (hopefully) the same binary data to be returned in the Response. As a
        result it outright rejects 'params' containing bytes below 0x20, and
        has the potential to go horribly wrong and land you in encoding hell.

        Basically, you probably want to base64 params before giving it to a
        Request object.

    .. method:: __str__(self)

        Evaluating ``str(request_object)`` gives a query string, excluding
        the ``?``

    """

    _printable_regexp = re.compile("^[\\x20-\\x7E]+$")

    def __init__(self, url, desc=None, aauth=None, iact=None, msg=None,
                 params=None, fail=None, encode_strings=True):

        if not (iact is True or iact is False or iact is None):
            raise ValueError("iact should be True, False or None")

        if aauth == frozenset():
            raise ValueError("aauth may not be the empty set")

        self.ver = 3
        self.url = url
        self.desc = desc
        self.aauth = aauth
        self.iact = iact
        self.msg = msg
        self.params = params
        self.fail = fail

        # We encode now so that we can check the parameters are sane,
        # though the encoded versions aren't needed until __str__

        if encode_strings:
            self._desc_encoded = self._encode_printable(desc)
            self._msg_encoded = self._encode_printable(msg)
        else:
            self._desc_encoded = desc
            self._msg_encoded = msg

        self._check_printable(self._desc_encoded, "desc")
        self._check_printable(self._msg_encoded, "msg")

    def __str__(self):
        """Returns a query string, for this Request (excluding the '?')"""
        query_params = {"ver": self.ver, "url": self.url}

        if self._desc_encoded is not None:
            query_params["desc"] = self._desc_encoded

        if self.aauth:
            query_params["aauth"] = ','.join(str(a) for a in self.aauth)

        if self.iact is True:
            query_params["iact"] = "yes"
        elif self.iact is False:
            query_params["iact"] = "no"

        if self._msg_encoded is not None:
            query_params["msg"] = self._msg_encoded

        if self.params is not None:
            query_params["params"] = self.params

        if self.fail:
            query_params["fail"] = "yes"

        return urlencode(query_params)

    def __repr__(self):
        """Summarise the Request object"""
        return "<ucam_webauth.Request url={0!r}>".format(self.url)

    @classmethod
    def _encode_printable(cls, string):
        if string is None:
            return None

        # We don't need to worry about <>; but & does need to be escaped.
        string = string.replace("&", "&amp;")
        # Care around python2/python3
        return string.encode("ascii", "xmlcharrefreplace").decode("ascii")

    @classmethod
    def _check_printable(cls, string, parameter="String"):
        if string is None:
            return

        if not cls._printable_regexp.match(string):
            raise ValueError("{0} contains non-printable characters"
                                .format(parameter))


class Response(object):
    """
    A Response from the WLS

    Constructed by parsing `string`, the 'encoded response string' from the
    WLS.

    The Response class has the following attributes, which must be set by
    subclassing it (see :class:`raven.Response`):

    .. attribute:: old_version_ptags

        A :class:`set` of :class:`str` objects

        The ptags attribute is set to this value if the version of the
        response is less than 3

    .. attribute:: keys

        A dict mapping key identifiers (`kid`) to a RSA public key
        (which must be an object with a ``verify(digest, signature)``
        method that returns a :class:`bool`)

    A Response object has the following attributes:

    **Always present**

    .. attribute:: ver

        response protocol version
        (:class:`int`)

    .. attribute:: status

        response status
        (:class:`Status` constant)

    .. attribute:: msg

        a text message describing the status of the authentication
        request, suitable for display to the end-user
        (:class:`str`)

    .. attribute:: issue

        response creation time
        (:class:`datetime`, timezone naive - the values are UTC)

    .. attribute:: id

        an "identifier" for the response.
        (:class:`int`)

        The tuple (issue, id) is guaranteed to be unique

    .. attribute:: url

        the value of `url` supplied in the request, or equivalently,
        the URL to which this response was delivered
        (:class:`str`)

    .. attribute:: success

        shorthand for ``status == STATUS_SUCCESS``
        (:class:`bool`)

    .. attribute:: params

        a copy of `params` from the request
        (:class:`str`)

    .. attribute:: signed

        whether the signature was present and has been verified
        (:class:`bool`)

        Note that a present but invalid signature will produce an exception
        when parsed.

    **Present if authentication was successful, otherwise ``None``:**

    .. attribute:: principal:

        the authenticated identity of the user
        (:class:`str`)

    .. attribute:: ptags

        attributes or properties of the principal
        (:class:`frozenset` of :class:`str` objects)

    .. attribute:: auth

        method of authentication used
        (:class:`AuthenticationType` constant, or ``None``)

        If authentication was not established by interaction (i.e., the
        client was already authenticated) then `auth` is ``None``

    .. attribute:: sso

        previous successful authentication types used
        (:class:`frozenset` of :class:`AuthenticationType` constants)

        `sso` will not be the empty set if auth is ``None``

    **Optional if authentication was successful, otherwise ``None``:**

    .. attribute:: life

        remaining life of the user's WLS session
        (:class:`int`, in seconds)

    **Required if signed is True:**

    .. attribute:: kid

        identifies the RSA key used to sign the request
        (:class:`str`)

    """

    # Note that "ptags" is omitted in a version 1 response.
    _response_fields = ("ver", "status", "msg", "issue", "id", "url",
                        "principal", "ptags", "auth", "sso", "life",
                        "params", "kid", "sig")
    _b64_trans = maketrans(b"-._", b"+/=")

    old_version_ptags = frozenset()
    keys = {}

    def __init__(self, string):
        if sys.version_info[0] >= 3 and \
                isinstance(string, (bytes, bytearray)):
            # rfc3986: urls should be utf-8
            string = string.decode('utf-8')

        values, self.digested_data = self._split_string(string)

        if len(values) != len(self._response_fields):
            raise ValueError("Incorrect number of values in response")

        for key, value in zip(self._response_fields, values):
            setattr(self, key, value)

        self._parse_base_types()
        self._fixup()
        self._verify()
        self._sanity_check()

    def __repr__(self):
        """Summarise the Response object"""
        extra = ""
        if self.success:
            if self.ptags:
                ptags = ", ".join(self.ptags)
                extra = " ({0})".format(ptags)
            s = "<ucam_webauth.Response success: {r.principal}{extra}>"
        else:
            s = "<ucam_webauth.Response failed: {r.status}>"
        return s.format(r=self, extra=extra)

    def _split_string(self, string):
        """
        Split the response string into values

        Returns values, digested: a list of strings (the unparsed values) and
        the string that is hashed to calculate the signature
        """

        values = string.split("!")

        assert self._response_fields[-2:] == ("kid", "sig")
        # urls should be utf-8, so this should recover the original data
        digested = '!'.join(values[:-2]).encode('utf-8')

        ver = int(values[0])

        if ver == 1 or ver == 2:
            if len(values) != len(self._response_fields) - 1:
                raise ValueError("Incorrect number of values in response")

            values.insert(self._response_fields.index("ptags"), '')

        elif ver > 3:
            # Since we send ver=3 in the request, this shouldn't ever happen
            raise ValueError("Response version unsupported")

        return values, digested

    def _parse_base_types(self):
        """
        Parse integers, decode strings, split lists

        Set empty values to None where appropriate
        (i.e., except params and lists. lists are set to None in _fixup).
        """

        if len(self.status) != 3:
            raise ValueError("Invalid status")

        # integers
        self.ver = int(self.ver)
        self.status = int(self.status)

        # strings, required/optional checked in _sanity_check
        for key in ("id", "url", "msg", "principal", "auth", "kid"):
            if getattr(self, key) == '':
                setattr(self, key, None)
            else:
                setattr(self, key, self._decode_value(getattr(self, key)))

        # datetime
        self.issue = datetime.strptime(self.issue, "%Y%m%dT%H%M%SZ")

        # comma_separated: ptags, sso, required/optional checked in _fixup
        for key in ("ptags", "sso"):
            if getattr(self, key) == '':
                setattr(self, key, frozenset())
            else:
                encoded_strings = getattr(self, key).split(',')
                strings = frozenset(self._decode_value(s)
                                    for s in encoded_strings)
                setattr(self, key, strings)

        # optional integer, required empty checked in _sanity_check
        if self.life == '':
            self.life = None
        else:
            self.life = int(self.life)

        # string, but keep empty as ''
        self.params = self._decode_value(self.params)

        # base64 variant, verified and required-checked in _verify
        if self.sig != '':
            self.sig = self._webauth_b64decode(self.sig)
        else:
            self.sig = None

    @classmethod
    def _decode_value(cls, encoded):
        """Unquote '!' and '%' in response field values"""
        # From waa2wls-protocol.txt:
        # If the characters '!'  or '%' appear in any field value they MUST
        # be replaced by their %-encoded representation before concatenation.
        # Characters other than '!' and '%' MUST NOT be encoded at this stage.

        value = unquote(encoded)

        # We shouldn't decode any %xx sequences except those for '!' and '%'
        # (%xx sequences present in the value before encoding would have been
        # rendered inert by % -> %25)
        if value.replace("%", "%25").replace("!", "%21") != encoded:
            raise ValueError("The WLS encoded characters other than % and !")

        return value

    @classmethod
    def _webauth_b64decode(cls, string):
        """Decode Ucam-webauth's variant of base64"""
        # Need to lose the unicode for translate and b64decode
        string = string.encode("ascii")
        string = string.translate(cls._b64_trans)
        try:
            return b64decode(string, validate=True)
        except TypeError: # apparently
            raise ValueError("Invalid base64 (sig)")

    def _fixup(self):
        """
        Miscellaneous parsing steps

        Replace status integer / authentication type strings with their
        module level constant objects.

        Set self.success

        Add default ptags for older versions, replace lists that are required
        by the protocol to be empty with None.
        """

        if self.status in STATUS_CODES:
            self.status = STATUS_CODES[self.status]
        else:
            raise ValueError("Unrecognised status code {0}"
                                .format(self.status))

        self.success = (self.status == STATUS_SUCCESS)

        if self.auth is not None:
            self.auth = self._atype_obj(self.auth)

        if self.success:
            if self.ver < 3:
                self.ptags = self.old_version_ptags

            self.sso = frozenset(self._atype_obj(a) for a in self.sso)

        else:
            if self.ptags != set():
                raise ValueError("Failed, yet ptags is not empty")
            self.ptags = None

            if self.sso != set():
                raise ValueError("Failed, yet sso is not empty")
            self.sso = None

    @classmethod
    def _atype_obj(cls, auth):
        """Convert a string to an AuthenticationType constant"""
        if auth == "pwd":
            return ATYPE_PWD
        else:
            raise ValueError("Unrecognised authentication type {0}"
                                .format(auth))

    def _verify(self):
        """
        Verify the signature in response, if present

        sets self.signed = True if successful; will raise ValueError if a
        successful response is not signed.
        """

        if (self.sig is None) != (self.kid is None):
            raise ValueError("sig and kid must either both be present or "
                                "both be empty")

        if self.sig is not None:
            if self.kid not in self.keys:
                raise ValueError("Unrecognised kid")

            key = self.keys[self.kid]
            self.digest = sha1(self.digested_data).digest()

            if not key.verify(self.digest, self.sig):
                raise ValueError("Signature invalid")

            self.signed = True

        else:
            self.signed = False

        if self.success and not self.signed:
            raise ValueError("Successful responses must be signed")

    def _sanity_check(self):
        """Miscellaneous sanity checks that are not included in parsing."""

        for key in ("ver", "status", "issue", "id", "url"):
            if getattr(self, key) is None:
                raise ValueError("{0} is required".format(key))

        if self.success:
            if self.principal is None:
                raise ValueError("Success, yet principal is empty")
            if self.auth is None and self.sso == set():
                raise ValueError("Success, yet neither auth nor sso provided")
        else:
            for key in ("principal", "auth", "life"):
                if getattr(self, key) is not None:
                    raise ValueError("Failed, yet {0} is not empty"
                                        .format(key))

    def check_iact_aauth(self, iact, aauth):
        """
        Check that the WLS honoured `iact`, `aauth`

        This method checks that `self.auth`, `self.sso` are consistent with
        the `iact` and `aauth`, which should be the same as the values used
        to construct the :class:`Request`.
        """

        if iact is True:
            # must have authenticated just now:
            if self.auth is None:
                return False

            # further, must have used one of the allowed methods
            if aauth is not None and self.auth not in aauth:
                return False

            return True

        elif iact is False:
            # shouldn't have just authenticated
            if self.auth is not None:
                return False

            # but should have used one of the previous auth methods
            if aauth is not None and aauth & self.sso == set():
                return False

            return True

        else:
            # must have authenticated somehow at some point
            # (self.auth is not None or self.sso != set() is checked in
            # _sanity_check)
            # ... using an allowed method
            return aauth is None or \
                    self.auth in aauth or \
                    aauth & self.sso != set()
