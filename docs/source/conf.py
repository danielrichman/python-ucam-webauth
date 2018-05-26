# -*- coding: utf-8 -*-

import sys
import os.path

# We need to be able to import ourselves to generate module docs
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# mock out the external C module, since it might not be built,
# and isn't documented. The RSA objects returned are documented manually
# by .. attribute, so returning None shouldn't be a problem
class MockRSA(object):
    def load_key(self, data):
        return None
    RSA = object

import ucam_webauth
ucam_webauth.rsa = MockRSA()
sys.modules["ucam_webauth.rsa"] = ucam_webauth.rsa


extensions = ['sphinx.ext.autodoc', 'sphinx.ext.viewcode']

source_suffix = '.rst'
master_doc = 'index'

project = u'ucam-webauth'
copyright = u'2013, Daniel Richman'
version = release = '0.9.2'

exclude_patterns = []
pygments_style = 'sphinx'
html_theme = 'default'
html_use_opensearch = 'https://python-ucam-webauth.readthedocs.io/en/latest/'
htmlhelp_basename = 'python-ravendoc'

autodoc_member_order = "bysource"
