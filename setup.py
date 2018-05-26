import os.path
from setuptools import setup, Extension

filename = os.path.join(os.path.dirname(__file__), 'description.rst')
with open(filename) as f:
    long_description = f.read()

rsamodule = Extension('ucam_webauth.rsa',
                      sources=['ucam_webauth/rsa.c'],
                      libraries=["ssl", "crypto"])

setup(
    name = "python-ucam-webauth",
    version = "0.9.2",
    packages = ["ucam_webauth", "ucam_webauth.raven"],
    package_data = {"ucam_webauth": ["raven/keys/pubkey*"]},
    ext_modules = [rsamodule],
    install_requires = ["setuptools"],
    extras_require = {"flask_glue": ["Flask"]},
    tests_require = ["nose", "Flask"],
    test_suite = 'nose.collector',

    author = "Daniel Richman",
    author_email = "main@danielrichman.co.uk",
    description = "Ucam-webauth and Raven application agent in Python",
    long_description = long_description,
    license="BSD-2-Clause",
    keywords = "Raven Cambridge ucam-webauth",
    url = "http://github.com/danielrichman/python-ucam-webauth",

    classifiers = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Framework :: Flask",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content :: "
                    "CGI Tools/Libraries",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3"
    ]
)

# python setup.py test
# python setup.py build_sphinx sdist upload upload_docs
