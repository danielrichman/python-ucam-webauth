# -*- coding: utf-8 -*-

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
