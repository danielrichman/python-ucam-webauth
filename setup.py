import os.path
from setuptools import setup

readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
with open(readme_file) as f:
    readme = f.read()

setup(
    name = "python-raven",
    version = "0.3",
    packages = ["raven", "ucam_webauth"],
    package_data = {"raven": ["keys/pubkey*.crt"]},
    install_requires = ["M2Crypto", "setuptools"],
    extras_require = {"flask_glue": ["Flask"]},
    tests_require = ["nose", "Flask"],
    test_suite = 'nose.collector',

    author = "Daniel Richman",
    author_email = "main@danielrichman.co.uk",
    description = "Ucam-webauth and Raven application agent in Python",
    long_description = readme,
    license="GNU Lesser General Public License Version 3",
    keywords = "Raven Cambridge ucam-webauth",
    url = "http://github.com/danielrichman/python-raven",

    classifiers = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2"
    ]
)

# python setup.py test
# python setup.py build_sphinx sdist upload upload_sphinx
