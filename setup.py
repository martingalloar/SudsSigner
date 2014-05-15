#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Basic setup script. Still no dependecy information


# python-libxml2 / libxml2-python should be installed before
# because it does not install from PyPi.
# It's part of libxml2 and may be present as separate package
# e.g. python-libxml2 on Ubuntu, libxml2-python on RHEL/CentOS
# All other dependencies should work.
# Tested with virtualenv --distribute and python 2.7 on Ubuntu 12.04
# after copying libxml2 manually from system folder.
from setuptools import setup


setup(name='sudssigner',
      version='0.9',
      packages=['sudssigner'],
      install_requires=[
        'lxml', 'pyopenssl', 'suds-jurko>=0.4.1',
        'PyXMLSec>=0.3.1'],
      dependency_links=['https://github.com/htj/suds-htj/tarball/master#egg=suds-0.4.1'],
)
