from __future__ import unicode_literals

import sys
import os.path
import base64
import hashlib
from nose.tools import assert_raises

from ucam_webauth.rsa import load_key, RSA

key_pkcs1s = {}
digests = {}
signatures = {}

key_names = ['a', 'b']
data_names = ['1', '2']
b64_data = set(["2"])
signature_names = ['1a', '1b', '2a', '2b']

rsa_cases_dir = os.path.join(os.path.dirname(__file__), 'rsa_cases')

for name in key_names:
    filename = os.path.join(rsa_cases_dir, 'keys', name)
    with open(filename, 'rb') as f:
        key_pkcs1s[name] = f.read()

for name in data_names:
    filename = os.path.join(rsa_cases_dir, 'data', name)
    if name in b64_data:
        filename += ".b64"
    with open(filename, 'rb') as f:
        data = f.read()
    if name in b64_data:
        data = base64.b64decode(data)
    digest = hashlib.sha1(data).digest()
    digests[name] = digest

for name in signature_names:
    filename = os.path.join(rsa_cases_dir, 'signatures', name + '.b64')
    with open(filename, 'rb') as f:
        data = base64.b64decode(f.read())
    signatures[name] = data

del rsa_cases_dir, key_names, data_names, b64_data, signature_names
del name, filename, f, data, digest


class TestRSA(object):
    def test_good_signatures(self):
        for key_name, key_pkcs1 in key_pkcs1s.items():
            key = load_key(key_pkcs1)

            for data_name, digest in digests.items():
                signature_name = data_name + key_name
                signature = signatures[signature_name]

                assert key.verify(digest, signature)

    def test_bad_signatures(self):
        for key_name, key_pkcs1 in key_pkcs1s.items():
            key = load_key(key_pkcs1)

            for data_name, digest in digests.items():
                good_signature_name = data_name + key_name

                for signature_name, signature in signatures.items():
                    if signature_name == good_signature_name:
                        continue
                    else:
                        assert not key.verify(digest, signature)

    def test_rejects_garbage_key(self):
        assert_raises(TypeError, load_key, 123)
        assert_raises(ValueError, load_key, b"asdfasdf")
        if sys.version_info[0] >= 3:
            assert_raises(TypeError, load_key, "asdfasdf")

    def test_rejects_garbage_digest(self):
        key = load_key(key_pkcs1s["a"])
        signature = signatures["1a"]
        assert_raises(TypeError, key.verify, 123, signature)
        if sys.version_info[0] >= 3:
            assert_raises(TypeError, key.verify, "short digest", signature)

    def test_rejects_garbage_signature(self):
        key = load_key(key_pkcs1s["a"])
        digest = digests['1']
        assert_raises(TypeError, key.verify, digest, 123)
        if sys.version_info[0] >= 3:
            assert_raises(TypeError, key.verify, digest, "asdf")

    def test_rejects_bad_length_digest(self):
        key = load_key(key_pkcs1s["a"])
        signature = signatures["1a"]
        assert_raises(ValueError, key.verify, b"short digest", signature)
