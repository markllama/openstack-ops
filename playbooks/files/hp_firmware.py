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
import platform
import re
import subprocess
import sys

# ------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------
#
VERSION=0.1
hp_health_version = "10.90"

defaults = {
  "data_file": "./firmware_data.json",
  "yum_repo_file": "/etc/yum.repos.d/hp-spp.plan"
}

redhat_packages = [
    "dmidecode",
    "ethtool",
    "pciutils",
    "lshw",
    "ipmitool"
]

hp_packages = [
    "ssacli",
    "hponcfg"
]

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
# System Probe Commands
# ------------------------------------------------------------------------
#
def system_product_name():
  """
  Retrieve the system-product-name from DMI and return a string
  """
  cmd = "/usr/bin/env dmidecode -s system-product-name"
  p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  (response, stdErr) = p.communicate()
  if p.returncode != 0:
    response = "Family Model Generation"

  return str(response.strip().decode(encoding='UTF-8'))

def hp_model():
  """
  Pull the system product name from BIOS and extract the HP model information
  """
  prod_string = system_product_name()
  prod_fields = prod_string.split()
  prod_spec = {
    'family': str(prod_fields[0]).lower(),
    'model': str(prod_fields[1]).lower(),
    'generation': str(prod_fields[2]).lower()
  }
  return prod_spec

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

  if opts.debug:
    logging.basicConfig(level=logging.DEBUG)
  else:
     logging.basicConfig(level=logging.WARNING)

  # Read the update spec 
  if os.path.isfile(opts.firmware_data):
    logging.info("loading firmware data from {}".format(opts.firmware_data))
    firmware_data = json.load(open(opts.firmware_data))
  else:
    logging.warning("firmware data file missing: {}".format(opts.firmware_data))
    pass

  # Determine the HP hardware model and generation
  #hw_spec = hp_model()['generation'].lower() if opts.hw_gen == None else opts.hw_gen
  #logging.info("HP HW gen: {}".format(hw_gen))

  # check OS
  if is_redhat():
    package_status = package_versions(redhat_packages)
    logging.debug("package status = {}".format(package_status))

    missing_packages = [ p for p in package_status.keys() if package_status[p] == None]

    # install required packages
    if opts.install:
      logging.info("installing missing packages: {}".format(", ".join(missing_packages)))
      update_redhat_packages(missing_packages)

    # add/update the hp-spp yum repo
    if opts.install:
      yum_fd = open(opts.yum_repo_file, "w+")
      write_hp_firmware_yum_repo_spec(system_spec, rpm_source='hp', repo_fd=yum_fd)
      yum_fd.close()
    
    package_status = package_versions(hp_packages)
    logging.debug("package status = {}".format(package_status))

    missing_packages = [ p for p in package_status.keys() if package_status[p] == None]

    # install required packages
    if opts.install:
      logging.info("installing missing packages: {}".format(", ".join(missing_packages)))
      update_redhat_packages(missing_packages)


  hw_gen = hp_model()['generation'].lower() if opts.hw_gen == None else opts.hw_gen
  logging.info("HP HW gen: {}".format(hw_gen))

  # survey firmware(s) version(s)

  
  #nics = get_broadcom_nics()
  #firmware_specs = load_firmware_data("firmware_list.json")

  # create/update hp-spp yum repo file

  # update utility packages (if necessary)
  # - gen9 - hp-health package -> 10.90

  # get firmware packages

  # install firmware packages
