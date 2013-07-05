from setuptools import setup

setup(
    name = "python-raven",
    version = "0.1",
    packages = ["raven"],
    py_modules = ["ucam_webauth"],
    package_data = {"raven": ["keys/pubkey*.crt"]},
    install_requires = ["M2Crypto", "setuptools"],

    author = "Daniel Richman",
    author_email = "main@danielrichman.co.uk",
    description = "Ucam-webauth and Raven client in Python",
    license="GNU Lesser General Public License Version 3",
    keywords = "Raven Cambridge ucam-webauth",
    url = "http://github.com/danielrichman/python-raven",
)
