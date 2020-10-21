#!/usr/bin/env python
#
# Copyright 2019-Present, Rackspace US, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Update HP firmware on a host running RHEL 7


"""

# Minimal Python 2->3 portability
from __future__ import print_function

import argparse
import json
import os
import platform
import re
import subprocess
import sys

# ------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------
#
hp_health_version = "10.90"

# ------------------------------------------------------------------------
# CLI Argument Processing
# ------------------------------------------------------------------------
#
def process_cli(args):
  parser = argparse.ArgumentParser()

  
  opts = parser.parse_args(args)

  return opts


# ------------------------------------------------------------------------
# NIC discovery functions
# ------------------------------------------------------------------------
#
def get_nic_devices():
  """
  Return a list of NIC devices. Filter out vlans and virtual devices
  """
  # Collect the names of the current net interfaces
  nics = [ os.path.basename(n) for n in os.listdir('/sys/class/net') ]

  # Select the nic patterns that are of interest - no VLANs
  nic_pattern = re.compile("^(eth|em|eno)[0-9]+$")
  nics = [ n for n in nics if nic_pattern.match(n) ]
  return nics

def nic_is_broadcom(nic_name):
  """
  Return true if the given nic is a Broadcom device (uses tg3 driver)
  Search for a line containing "DRIVER=tg3"
  """
  is_broadcom = False

  dev_file = open("/sys/class/net/{}/device/uevent".format(nic_name),"r")

  # Only change the value if you find it
  for line in dev_file:
    if "DRIVER=tg3" in line:
      is_broadcom = True
      break

  dev_file.close()

  return is_broadcom

def get_broadcom_nics():
  """
  Return a list of broadcom nic devices
  """
  return [ d for d in get_nic_devices() if nic_is_broadcom(d) ]

# ------------------------------------------------------------------------
# Red Hat Functions
# ------------------------------------------------------------------------
#
def is_redhat():
  """
  Indicate if the host is running a Red Hat distribution
  """
  # The first ele
  return "Red Hat Enterprise Linux Server" == platform.linux_distribution()[0]


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

def write_yum_repo_spec(system_spec, rpm_source='hp'):
  """
  Create or update the YUM repository spec for the HP firmware packages
  """
  repo_filename = "/etc/yum.repos.d/hp-spp.repo"

  # set the hardware specific parts of the repo URL
  baseurl = yum_baseurl_templates[rpm_source].format(system_spec['spp-gen'], system_spec['spp-version'])
  repo_spec = yum_repo_template.format(baseurl)
    
  repo_fd = open(repo_filename, "w+")
  repo_fd.write(repo_spec)
  repo_fd.close()

def get_rpm_version(package_name):
  """
  Get the package version string for the provided package
  """

  # The rpm command to query the version of a package
  query_command_template = "rpm -q --qf '%{VERSION}' {}"
  query_command=query_command_template.format(package_name)
  
  # Run the query command
  get_version = subprocess.Popen(query_command, stdout=PIPE, stderr=PIPE, shell=True)

  # get the version string from the output. Stdout is the first element of the returned tuple
  version_string = get_version.communicate()[0].decode(encoding='UTF-8')

  return version_string

def cmp_version_string(vs0, vs1):
  """
  :param vs0: the first version string
  :param vs1: the second version string
  :return: int (1, 0, -1) for vs0 > = < vs1

  Compare two version strings of the form MM.mm[.bb]
  Where:
    MM - Major Version Number
    mm - Minor Version Number
    bb - Build Number

  TO DO: Check for different length 
  """

  v0 = [int(n) for n in vs0.split('.')]
  v1 = [int(n) for n in vs1.split('.')]

  # Compare the major numbers
  if v0[0] != v1[0]:
    return 1 if v0[0] > v1[0] else -1

  # Compare the minor numbers
  if v0[1] != v1[1]:
    return 1 if v0[1] > v1[1] else -1

  # Compare the build numbers
  if v0[2] != v1[2]:
    return 1 if v0[2] > v1[2] else -1

  # The version strings are the same
  return 0

# ------------------------------------------------------------------------
# Data Load/Access function
# ------------------------------------------------------------------------
#
def _decode_list(data):
  """
  Convert all string elements in a list to ASCII
  """
  rv = []
  for item in data:
    if isinstance(item, unicode):
      item = item.encode('utf-8')
    elif isinstance(item, list):
      item = _decode_list(item)
    elif isinstance(item, dict):
      item = _decode_dict(item)
      rv.append(item)
  return rv
    
def _decode_dict(data):
  """
  Convert all string elements in a dict to ASCII
  """
  rv = {}
  for key, value in data.iteritems():
    if isinstance(key, unicode):
      key = key.encode('utf-8')
    if isinstance(value, unicode):
      value = value.encode('utf-8')
    elif isinstance(value, list):
      value = _decode_list(value)
    elif isinstance(value, dict):
      value = _decode_dict(value)
    rv[key] = value
  return rv
  
def load_firmware_data(filename):
  """
  Load a set of firmware specs for a list of supported HP server types
  """

  return json.load(open(filename), object_hook=_decode_dict)

def get_firmware():
  pass

def install_firmware_rpm():
  pass

def install_firmware_cpio():
  pass

# ========================================================================
# MAIN
# ========================================================================
if __name__ == "__main__":
  opts = process_cli(sys.argv[1:])

  #nics = get_broadcom_nics()
  #firmware_specs = load_firmware_data("firmware_list.json")

  # create/update hp-spp yum repo file

  # update utility packages (if necessary)
  # - gen9 - hp-health package -> 10.90

  # get firmware packages

  # install firmware packages
