from glob import glob
from distutils.command.install import INSTALL_SCHEMES
from setuptools import setup
import token_auth.get_version

for scheme in INSTALL_SCHEMES.values():
    scheme["data"] = scheme["purelib"]

data_files = [
    ["token_auth/templates/base_templates", glob("token_auth/templates/base_templates/*.html")]
]

VERSION = token_auth.get_version

setup(
    name='django-token_auth',
    version = VERSION,
    url = 'http://bitbucket.org/mogga/django-token_auth/',
    license = 'BSD',
    description = "app that provides limited authentication via hash-type URL.",
    author = 'Oyvind Saltvik',
    author_email = 'oyvind.saltvik@gmail.com',
    packages = ["token_auth"], 
    package_dir = {"token_auth": "token_auth"},
    data_files = data_files,
    install_requires = ["setuptools"],
    classifiers = [
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords = 'python django hash auth'
)
