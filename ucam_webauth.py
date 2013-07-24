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
Ucam-webauth

The ucam_webauth module implements version 3 of the WAA to WLS protocol as
was defined at https://raven.cam.ac.uk/project/waa2wls-protocol.txt at the
time of writing (though that URL may have since been replaced with a newer
version). A copy is included. More information can be found at
https://raven.cam.ac.uk/project/.

WAA: Web Application Agent (i.e., an application using this module)
WLS: Web Logon Service (typically Raven)
"""

__name__ = "ucam_webauth"
__version__ = "0.1"
__author__ = "Daniel Richman"
__copyright__ = "Copyright 2013 Daniel Richman"
__email__ = "main@danielrichman.co.uk"
__license__ = "LGPL3"


import sys
import re
from string import maketrans
from datetime import datetime
from base64 import b64decode
from hashlib import sha1

from M2Crypto.RSA import RSAError

if sys.version_info[0] >= 3:
    from urllib.parse import unquote, urlencode
else:
    from urllib import unquote, urlencode


__all__ = ["Status", "ErrorStatus", "STATUS_CODE_LIST", "STATUS_CODES",
           "ATYPE_PWD", "Response"]


class AuthenticationType(object):
    """
    An Authentication Type

    name: the name by which Ucam-webauth knows it
    description: a sentence describing it

    Note that comparing an AuthenticationType object with a string (or another
    AuthenticationType object) will compare the name attribute only.
    Further, str(atype) == atype.name.
    """

    def __init__(self, name, description):
        self.name = name
        self.description = description
    def __str__(self):
        return self.name
    def __repr__(self):
        return "<ucam_webauth.AuthenticationType {0}>".format(self.name)
    def __eq__(self, other):
        if isinstance(other, AuthenticationType):
            return self.name == other.name
        else:
            return self.name == other

ATYPE_PWD = AuthenticationType("pwd", "Username and password")


class Status(object):
    """
    A WLS response Status

    code: a (three digit) integer
    name: short name for the status
    description: a sentence describing the status

    Note that comparing a Status object with an integer (or another Status
    object) will compare the code attribute only. Further,
    int(status_object) == status_object.code
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
    def __eq__(self, other):
        if isinstance(other, Status):
            return self.code == other.code
        elif isinstance(other, int):
            return self.code == other
        else:
            return False

class ErrorStatus(Status, Exception):
    """A Status that is not 'success' (200)"""
    def __init__(self, code, name, description):
        Status.__init__(self, code, name, description)
        Exception.__init__(self, "{0} {1}".format(code, description))

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

    Parameters:

        url: (str) a fully qualified URL; the user will be returned here
             (along with the Response as a query parameter) afterwards
        desc: (str) optional description of the resource/website (see below)
        aauth: (set of AuthenticationTypes) optional set of permissible
               authentication types that we require the user to use one of
               (if empty, the WLS uses its default set)
        iact: (bool or None) interaction required / forbidden

          - True: the user must re-authenticate
          - False: no interaction with the user is permitted
            (the request will only succeed if the user's identity can be
            returned without interacting at all)
          - None (default): interacts if required

        msg: (str) optional message explaining why authentication is required
             (see below)
        params: (str) data, which is returned unaltered in the Response
        fail: (bool) if True, and authentication fails, the WLS must show an
              error message and not redirect back to the WAA.

    msg and desc encoding:

    The 'msg' and 'desc' parameters are restricted to printable ASCII
    characters (0x20 - 0x7e). The WLS will convert '<' and '>' to '&lt;' and
    '&gt;' before using either string in HTML, preventing the inclusion of
    markup. However, it does not touch '&', so HTML character and numeric
    entities may be used to represent other characters.

    If encode_strings is True, & will be escaped to '&amp;', and non-ascii
    characters in msg and dseg will be converted to their numeric entities.

    An error will be raised if non-printable-ASCII characters then remain
    in msg or desc.

    params:

    The ucam-webauth protocol does not specify any restrictions on the content
    of params. However, awful things may happen if you put arbitary binary
    data in here. The Raven server appears to interpret non-ascii contents
    as latin-1, turn them into html entities in order to put them in a hidden
    HTML input element, then turn them back into (hopefully) the same binary
    data to be returned in the Response. As a result it outright rejects
    'params' containing bytes below 0x20, and has the potential to go horribly
    wrong and land you in encoding hell.

    Basically, you probably want to base64 params before giving it to a
    Request object.
    """

    _printable_regexp = re.compile("^[\\x20-\\x7E]+$")

    def __init__(self, url, desc=None, aauth=None, iact=None, msg=None,
                 params=None, fail=None, encode_strings=True):

        if not (iact is True or iact is False or iact is None):
            raise ValueError("iact should be True, False or None")

        self.ver = 3
        self.url = url
        self.desc = desc
        self.aauth = aauth
        self.iact = iact
        self.msg = msg
        self.params = params
        self.fail = fail

        # We encode now so that we can check the parameters are sane,
        # though the encoded versions arn't needed until __str__

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

    Constructed by parsing 'string', the 'encoded response string' from the
    WLS.


    The Response class has the following attributes, set by subclassing:

        old_version_ptags: (set of strings) ptags to use if ver < 3
        keys: (dict) maps key identifiers 'kid' to a RSA public key
              (an object with a verify(data, signature, algo) method,
              e.g. M2Crypto.RSA.RSA_pub)


    A Response object has the following attributes:

    Always present:

        ver: (int) response protocol version
        status: (Status object) response status
        msg: (str) a text message describing the status of the authentication
             request, suitable for display to the end-user
        issue: (datetime (tz naive; values are UTC)) response creation time
        id: (int) an "identifier" for the response. (issue, id) is unique
        url: the value of url supplied in the request
        success: (bool) shorthand for status == STATUS_SUCCESS
        params: (str) a copy of params from the request
        signed: (bool) whether the signature was present and has been verified

    Present if authentication was successful, otherwise None:

        principal: (str) the authenticated identity of the user (if successful)
        ptags: (set of strs) attributes or properties of the principal

    Present if authentication was established by interaction, otherwise None:

        auth: (AuthenticationType) method of authentication used

    If authentication was successful, then sso is present. sso may not be the
    empty list if auth is None. sso is None if authentication was unsuccessful

        sso: (set of AuthenticationTypes) previous successful authentication
             types used

    Optional if authentication was successful, otherwise None:

        life: (int, seconds) remaining life of the users' WLS session

    Required if signed is True:

        kid: (str) identifies the RSA key used to sign the request

    """

    # Note that "ptags" is ommitted in a version 1 response.
    _response_fields = ("ver", "status", "msg", "issue", "id", "url",
                        "principal", "ptags", "auth", "sso", "life",
                        "params", "kid", "sig")
    _b64_trans = maketrans("-._", "+/=")

    old_version_ptags = set()
    keys = {}

    def __init__(self, string):
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
        Split the respone string into values

        Returns values, digested: a list of strings (the unparsed values) and
        the string that is hashed to calculate the signature
        """

        values = string.split("!")

        assert self._response_fields[-2:] == ("kid", "sig")
        digested = '!'.join(values[:-2])

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
                setattr(self, key, set())
            else:
                encoded_strings = getattr(self, key).split(',')
                strings = set(self._decode_value(s) for s in encoded_strings)
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
            return b64decode(string)
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

            self.sso = set(self._atype_obj(a) for a in self.sso)

        else:
            if self.ptags != set():
                raise ValueError("Failed, yet ptags is not empty")
            self.ptags = None

            if self.sso != set():
                raise ValueError("Failed, yet sso is not empty")
            self.sso = None

    @classmethod
    def _atype_obj(cls, auth):
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

            try:
                valid = key.verify(self.digest, self.sig, 'sha1')
            except RSAError:
                valid = False
            if not valid:
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
