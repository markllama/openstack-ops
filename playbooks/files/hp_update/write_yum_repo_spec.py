#!/bin/env python
from __future__ import print_function

import sys

"""
These are the patterns for the upstream repo URL and for the Rackspace mirror
"""
yum_baseurl_templates = {
  "hp": "https://downloads.linux.hpe.com/SDR/repo/spp-{}/rhel/$releasever/$basearch/{}",
  "rackspace": "http://mirror.rackspace.com/hp/SDR/repo/spp/rhel/$releasever/$basearch/current"
}

"""
This string is a template for the complete YUM repo file
"""
yum_repo_template = """\
[hp-spp]
name = HP Service Pack for ProliantPackage
baseurl = {}
enabled = 1
gpgcheck = 1
gpgkey = https://downloads.linux.hpe.com/SDR/repo/spp/GPG-KEY-spp
"""

def write_hp_firmware_yum_repo_spec(system_spec, rpm_source='hp', repo_fd=sys.stdout):
  """
  Create or update the YUM repository spec for the HP firmware packages
  """

  # set the hardware specific parts of the repo URL
  baseurl = yum_baseurl_templates[rpm_source].format(system_spec['spp-gen'], system_spec['spp-version'])
  repo_spec = yum_repo_template.format(baseurl)
    
  repo_fd.write(repo_spec)
  repo_fd.flush()

if __name__ == "__main__":

  mock_spec = {
    'spp-gen': 'foo',
    'spp-version': '1.0'
  }
  write_hp_firmware_yum_repo_spec(mock_spec)
  print("-----")
  write_hp_firmware_yum_repo_spec(mock_spec, rpm_source='rackspace')

  
