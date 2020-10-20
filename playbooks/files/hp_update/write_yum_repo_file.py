#!/bin/env python
from __future__ import print_function

repo_template = """\
[hp-spp]
name = HP Service Pack for ProliantPackage
baseurl = https://downloads.linux.hpe.com/SDR/repo/spp-{}/rhel/$releasever/$basearch/{}
enabled = 1
gpgcheck = 1
gpgkey = https://downloads.linux.hpe.com/SDR/repo/spp/GPG-KEY-spp"
"""
