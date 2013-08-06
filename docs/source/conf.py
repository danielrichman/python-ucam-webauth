# -*- coding: utf-8 -*-

import sys

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

project = u'python-raven'
copyright = u'2013, Daniel Richman'
version = release = '0.3'

exclude_patterns = []
pygments_style = 'sphinx'
html_theme = 'default'
html_use_opensearch = 'http://pythonhosted.org/python-raven/'
htmlhelp_basename = 'python-ravendoc'

autodoc_member_order = "bysource"
