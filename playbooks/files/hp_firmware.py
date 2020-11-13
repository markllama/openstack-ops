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
import logging
import os
import re
import subprocess
import sys
import yaml

try:
  import distro
except:
  import platform as distro

# ------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------
#
VERSION=0.1
hp_health_version = "10.90"

defaults = {
  "data_file": "./firmware.yaml",
  "yum_repo_file": "/etc/yum.repos.d/hp-spp.repo"
}

requirements = {
  'redhat': [
    "dmidecode",
    "ethtool",
    "pciutils",
    "lshw",
    "ipmitool"
  ],
  'hp': [
    "hponcfg",
    "hp-health",
    "ssacli"
  ]
}

# ------------------------------------------------------------------------
# CLI Argument Processing
# ------------------------------------------------------------------------
#
# -D --firmware-data - A JSON file containing the firmware definitions for updates
#    default: ./firmware_data.json
# -f --flash - execute changes
#    default: false
# -i --install - install missing utilities and run check
#    default: false
# -r --yum-repo-file - where to install the yum repo file for HP packages
#
# -r --report - generate a report of current state
#    default: true
# -s --subsystems - ILO, SYS, NIC, INIC, RAID  (SYS == BIOS, INIC = Intel 10GB)
#    default: all
# -m --meltdown - install special BIOS firmware to mitigate spectre/meltdown CVE
#                 https://nvd.nist.gov/vuln/detail/CVE-2017-5754
# -M
# -G --hw-gen - Hardware Generation gen8, gen9, gen10 - overrides dmidecode response
#
# -B --fw-build - Firmware build - a string that is usually YYYY.MM.S where S is a serial number starting with 0 in the month

def process_cli(args):
  parser = argparse.ArgumentParser(
     description="HP Firmware Upgrade Utility v{}".format(VERSION))

  parser.add_argument(
    "--debug", "-d", action='store_true', default=False,
    help="write debug output"
  )

  parser.add_argument(
    "--product-name", "-p", 
    help="Specify the HP product string. Override the dmidecode response"
  )

  parser.add_argument(
    "--fw-build", "-B", required=False,
    help="The build string to use for the HP tools YUM repo baseurl. Overrides the values from the firmware-data" 
  )

  parser.add_argument(
    "--firmware-data", "-D", default=defaults['data_file'],
    help="The location of a JSON file containing firmware data"
  )
  
  parser.add_argument(
    "--flash", "-f", action='store_true', default=False,
    help="update the indicated firmware systems"
  )

  parser.add_argument(
    "--install", "-i", action='store_true', default=False,
    help="install required packages for status queries"
  )

  parser.add_argument(
    "--yum-repo-file", "-y", default=defaults['yum_repo_file'],
    help="the location of the HP SPP yum repository file"
  )

  parser.add_argument(
    "--report", "-r", action='store_true', default=False,
    help="generate a JSON formatted report of the current firmware versions"
  )

  #
  subsys_selector=parser.add_mutually_exclusive_group()
  subsys_selector.add_argument(
    "--all", "-a", action='store_const', dest='subsystems', const=['ilo', 'sys', 'nic', 'inic', 'raid'],
    help="update all subsystems"
  )
  
  subsys_selector.add_argument(
    "--subsystem", "-s", action='append', type=str, nargs='*', dest="subsystems",
    choices=['ilo', 'sys', 'nic', 'inic', 'raid'],
    help="The set of firmware subsystems to query or update"
  )
  
  
  opts = parser.parse_args(args)

  return opts

# ------------------------------------------------------------------------
# Red Hat Functions
# ------------------------------------------------------------------------
#
def is_redhat():
  """
  Indicate if the host is running a Red Hat distribution
  """
  # The first element
  #try 
  return "Red Hat Enterprise Linux Server" == distro.linux_distribution()[0]

def package_versions(pkg_list):
  """
  Get the version of each package in the list
  If the package is not installed, None
  """
  pkg_status = {}
  
  cmd = "rpm -q --qf %{{VERSION}} {}"
  for pkg_name in pkg_list:
    p = subprocess.Popen(cmd.format(pkg_name).split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (version, dummy) = p.communicate()

    # Save the version in a map. None indicates a missing package
    pkg_status[pkg_name] = str(version.strip()) if p.returncode == 0 else None

  return pkg_status

  
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

def update_redhat_packages(packages=[]):
  """
  Install or update a set of packages provided.
  """

  cmd_template = "/bin/env yum -y install {}"
  cmd_string = cmd_template.format(" ".join(packages))
  logging.debug("yum update command: {}".format(cmd_string))
  
  yum_cmd = subprocess.Popen(cmd_string.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  (yum_out, yum_err) = yum_cmd.communicate()

  logging.debug("yum output: \n{}".format(yum_out))
  if yum_cmd.returncode != 0:
    logging.error("error updating packages: {}".format(yum_err))

  # TODO - return the list of updated packages?
  # TODO - respond to error with an exception?


def check_redhat_prerequisites(install=False):
  """
  Install or update prerequisite packages on a Red Hat (RPM) based system.
  """

  package_status = package_versions(redhat_packages)
  logging.debug("package status = {}".format(package_status))

  missing_rhel_packages = [ p for p in package_status.keys() if package_status[p] == None]

  # install required packages
  if install:
    logging.info("installing missing rhel packages: {}".format(", ".join(missing_rhel_packages)))
    update_redhat_packages(missing_rhel_packages)

  # add/update the hp-spp yum repo
  if install:
    yum_fd = open(opts.yum_repo_file, "w+")
    write_hp_firmware_yum_repo_spec(system_spec, rpm_source='hp', repo_fd=yum_fd)
    yum_fd.close()
    
  package_status = package_versions(hp_packages)
  logging.debug("package status = {}".format(package_status))

  missing_hp_packages = [ p for p in package_status.keys() if package_status[p] == None]

  # install required packages
  if install:
    logging.info("installing missing hp packages: {}".format(", ".join(missing_hp_packages)))
    update_redhat_packages(missing_hp_packages)

def server_number():
  """
  Attempt to determine the Rackspace server number from the hostname
  """
  # find six (or 7?) numbers or '-'
  try:
    server_number = re.findall('\d{6}(?=-)', os.uname()[1])[0]
  except:
    server_number = "undefined"

  return server_number

def system_product_name():
  """
  Retrieve the system-product-name from DMI and return a string
  """
  cmd = "/usr/bin/env dmidecode -s system-product-name"
  p = subprocess.Popen(cmd.split(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (response, stdErr) = p.communicate()
  if p.returncode != 0:
    response = "Family Model Generation"


def load_firmware_data(filename):
  """
  Load a structure defining the
  """
  if filename.endswith('.yaml'):
    try:
      fw_data = yaml.load(open(filename), Loader=yaml.FullLoader)
    except:
      fw_data = yaml.load(open(filename))
    pass
  if filename.endswith('.json'):
    fw_data = json.load(open(filename), object_hook=_decode_dict)
  else:
    fw_data = None

  return fw_data

# ========================================================================
# MAIN
# ========================================================================
if __name__ == "__main__":
  opts = process_cli(sys.argv[1:])

  if opts.debug:
    logging.basicConfig(level=logging.DEBUG)
  else:
     logging.basicConfig(level=logging.WARNING)

  logging.info("updating firmware on subsystems: {}".format(opts.subsystems))
  
  # Read the update spec 
  if os.path.isfile(opts.firmware_data):
    logging.info("loading firmware data from {}".format(opts.firmware_data))
    firmware_data = load_firmware_data(opts.firmware_data)
  else:
    logging.warning("firmware data file missing: {}".format(opts.firmware_data))
    pass

  # check OS
  if is_redhat():
    check_redhat_prerequisites(opts.install)

  # Check the dmidecode output to determine which hardware we're on
  product_string = system_product_name()
  logging.info("Product String: {}".format(product_string))
