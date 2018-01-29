# -*- coding: utf-8 -*-


'''setup.py: setuptools control.'''


import re
from setuptools import setup
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), 'r') as f:
    long_description = f.read()

version = "0.0.10"

setup(
    name='aws-login',
    packages=['aws_login'],
    entry_points={
        'console_scripts': ['aws-login = aws_login.aws_login:main']
    },
    version=version,
    description='AWS login using the Secure Token Service',
    long_description=long_description,
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=['boto3', 'requests', 'configparser', 'click'],
    author='Martijn van Dongen',
    author_email='martijnvandongen@binx.io',
    url='https://github.com/binxio/aws-login',
)
