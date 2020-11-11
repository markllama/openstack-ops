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
import yaml

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
  "hponcfg",
  "hp-health",
  "ssacli"
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
  p = subprocess.Popen(cmd.split(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (response, stdErr) = p.communicate()
  if p.returncode != 0:
    response = "Family Model Generation"

  return str(response.strip().decode(encoding='UTF-8'))
def get_nic_firmware_version(nic_name):
  """
  Get the firmware version of a Broadcom nic (or other with ethtool)
  """

  cmd_template = "ethtool -i {}"
  cmd_string = cmd_template.format(nic_name)
  p = subprocess.Popen(cmd_string.split(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

  (response, stdout) = p.communicate()

  output_pattern = "^([^\s]+):(\s+(.*))?$"
  output_re = re.compile(output_pattern)
  nic_data = {}
  for line in response.split("\n"):
    m = output_re.match(str(line.strip()))
    if m:
      nic_data[m.group(1)] = m.group(3)

  return nic_data['firmware-version']
  
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
  nic_pattern = re.compile("^(eth|em|eno|ens[0-9]f)[0-9]+$")
  nics = [ n for n in nics if nic_pattern.match(n) ]
  return nics

def get_nic_driver(nic_name):
  """
  Return the driver module used by a giving nic device
  """
  driver = None

  dev_file = open("/sys/class/net/{}/device/uevent".format(nic_name),"r")
  # Only change the value if you find it
  for line in dev_file:
    if "DRIVER=" in line:
      driver = line.strip().split('=')[1]
      break
  dev_file.close()

  return driver

def get_system_firmware_version():
  """
  Get the version of the installed system firmware on HP systems
  """

  # One of the args is a space separated command string, so you can't split()
  # it
  cmd = ['hpasmcli', '-s',  'show server']
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  (response, stdout) = p.communicate()
  # TODO - check cmd return code

  rom_version = None
  for line in response.split('\n'):
    if line.startswith("ROM version"):
      rom_version = line.split(':')[1].strip()
      break;

  return rom_version

def get_ilo_firmware_version():
  """
  Get the firmware version of the installed ILO on an HP server
  """
  
  cmd_string = "hponcfg -h"
  p = subprocess.Popen(cmd_string.split(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (response, stderr) = p.communicate()

  firmware_re = re.compile("^Firmware Revision = (\d+\.\d+) ")

  ilo_version = None
  for line in response.split('\n'):
    match = firmware_re.match(line)
    if match:
      ilo_version = match.groups()[0]
      break

  return ilo_version

def get_nic_hardware():
  """
  TBD
  """
  list_nets_cmd_str = "lshw -c network -json"

  p = subprocess.Popen(list_nets_cmd_str.split(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (response, stdout) = p.communicate()

  # lshw JSON output needs some massaging before loading
  # The output from lshw in json has a problem with separating nodes
  # If you find two objects without a separator, add it.
  data = re.sub('}\s+{', "},{", response)
  # the data is a list of objects
  networks = json.loads("[\n" + data + "\n]", object_hook=_decode_dict)

  return networks

def nic_is_intel_10gbe(network_data):
  """
  TBD
  """

  product_string = "Ethernet Controller 10-Gigabit X540-AT2"
  vendor_string = "Intel Corporation"

  try:
    return network_data['product'] == product_string \
      and network_data['vendor'] == vendor_string \
      and 'logicalname' in network_data.keys()
  except:
    return False


def hp_nic_model_number(model_string):
  """
  TBD
  """
  # This is an odd looking pattern:
  #   It matches a set of HP model numbers
  #     
  model_pattern = '[3,5][6][0-9][A-Z,i]{1,3}-?[A-Z]{0,5}\+?'

  match = re.search(model_pattern, model_string)

  return None if match == None else match.group(0)

def pci_slot(network_data):
  """
  TBD
  """
  pci_slot_pattern = "^pci@[0-9a-zA-Z]{4}:([0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}\.\d)"
  pci_slot_re = re.compile(pci_slot_pattern)

  match = pci_slot_re.match(network_data['businfo'])
  
  return str(match.groups()[0])

  
def pci_device_subsystem(slot):
  """
  TBD
  """
  lspci_cmd_str = "lspci -v -s {}"

  p = subprocess.Popen(lspci_cmd_str.format(slot).split(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (response, stderr) = p.communicate()

  for line in response.split("\n"):
    if "Subsystem:" in line:
      return line.split(":")[1].strip()

  return None

def get_raid_firmware_version():
  """
  TBD
  """
  cmd_string = "ssacli controller all show config detail"
  p = subprocess.Popen(cmd_string.split(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (response, stdout) = p.communicate()

  rom_version = None
  for line in response.split("\n"):
    if "Firmware Version" in line:
      rom_version = line.split(':')[1].strip()
      break

  return rom_version

def get_intel_nic_firmware_versions(intel_nics):
  # for intel nics you need to break them down by model number
  # [ {'name': str, 'model': str, 'version': str} ]
  # add the model string
  for nic in intel_nics:
    nic['model'] = hp_nic_model_number(pci_device_subsystem(pci_slot(nic)))
    nic['firmware-version'] = get_nic_firmware_version(nic['logicalname'])

  # using list(set()) you can filter duplicate strings
  intel_models = list(set([ n['model'] for n in intel_nics]))

  # You can use set(list()) on strings and split them later.
  intel_mv_strings = list(set([ ':'.join([n['model'], n['firmware-version'] ]) for n in intel_nics]))

  # Collect the models and their current versions
  intel_model_versions = []
  for mv in intel_mv_strings:
    (model, version) = mv.split(':')
    intel_model_versions.append({'model': model, 'version': version })

  # add the list of nics that match
  for mv in intel_model_versions:
    mv['devices'] = [ n['logicalname'] for n in intel_nics if n['model'] == mv['model'] ]

  return intel_model_versions

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
      value = value.decode('utf-8')
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
# Reporting Functions
# ========================================================================
#
# These take a dict of the form:
#   {
#     'rom': <version>,
#     'ilom': <version>,
#     'raid': <version>,
#     'nic': <version>,
#     'inic': <version>
#   }
# current contains the detected values and available contains
# the update value available

# Report contains:
#  RAX server number 

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


class HostFirmware():
  """
  This class represents the firmware installed on an HP (and other?) host.
  """

  def __init__(self, data=None):
    if data == None:
      self._survey()
    else:
      self._load_data(data)

  def _survey(self):
    self.system = get_system_firmware_version()
    self.ilom = get_ilo_firmware_version()
    self.raid = get_raid_firmware_version()

    self.nics = {}
    nics = get_nic_devices()
    broadcom_nics = [ n for n in nics if "tg3" == get_nic_driver(n)]
    self.nics['broadcom'] = get_nic_firmware_version(broadcom_nics[0])
    
    # this is a list of dicts, one per nic
    intel_nics = [ n for n in get_nic_hardware() if nic_is_intel_10gbe(n) ]
    self.nics['intel'] = get_intel_nic_firmware_versions(intel_nics)
     
  def _load_data(self, data):
    """
    Load a firmware spec data structure into a HostFirmware objec
    """
    self.system = data['SYSTEM']['ver']
    self.ilom = data['ILO']['ver']
    self.raid = data['RAID']['ver']
    self.nics = {
      'broadcom': data['NIC']['ver'],
      'intel': data['INIC']['ver']
    }

  def compare(self, other):
    pass

class HostFirmwareEncoder(json.JSONEncoder):
  """
  TBD
  """
  def default(self, o):
    if isinstance(o, HostFirmware):
      return o.__dict__

    return None

def survey_host_firmware():
  """
  TBD
  """
  system_rom_version = get_system_firmware_version()
  ilo_version = get_ilo_firmware_version()
  raid_version = get_raid_firmware_version()
  nics = get_nic_devices()
  broadcom_nics = [ n for n in nics if "tg3" == get_nic_driver(n)]
  broadcom_nic_version = get_nic_firmware_version(broadcom_nics[0])

  # this is a list of dicts, one per nic
  intel_nics = [ n for n in get_nic_hardware() if nic_is_intel_10gbe(n) ]
  intel_nic_versions = get_intel_nic_firmware_versions(intel_nics)
     
  current = {
    'system': system_rom_version,
    'ilo': ilo_version,
    'raid': raid_version,
    'nics': {
      'broadcom': broadcom_nic_version,
      'intel': intel_nic_versions
    }
  }

  return current

def available_firmware_versions(model_firmware_data, intel_nic_models=None):
  """
  Collect the firmware versions available for the hardware present
  """

  available = {
    'system': model_firmware_data['SYSTEM']['ver'],
    'ilo': model_firmware_data['ILO']['ver'],
    'raid': model_firmware_data['RAID']['ver'],
    'nics': {
      'broadcom': model_firmware_data['NIC']['ver'],
      'intel': []
    }
  }

  if intel_nic_models != None:
    intel_nic_versions = [ {'model': m, 'vers': model_firmware_data['INIC']['ver'][m]} for m in intel_nic_models]
    available['nics']['intel'] = intel_nic_versions

  return available

def compare_firmware_versions(current, available):
  """
  Check of the "available" values match those pulled from the system.
  Non-match indicates that an update is required
  """

  
  pass

def report_text(current, available):
  """
  Report the current and avialable firmware values in human readable text
  """
  pass

def report_json(current, available):
  """
  Report the current and avialable firmware values in human readable text
  """
  #report = {
  #  'core_id': server_number(),
  #  'current': current,
  #  'available': available
  #}
  #print(json.dumps(report, indent=2))
  print(json.dumps(current, indent=2, cls=HostFirmwareEncoder))
  print(json.dumps(available, indent=2, cls=HostFirmwareEncoder))


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
    firmware_data_record = load_firmware_data(opts.firmware_data)
  else:
    logging.warning("firmware data file missing: {}".format(opts.firmware_data))
    pass

  firmware_base_url = firmware_data_record['firmware_cache_url']
  firmware_data = firmware_data_record['firmware_specs']
  
  logging.info("known systems: {}".format(firmware_data.keys()))

  # check OS
  if is_redhat():
    check_redhat_prerequisites(opts.install)

  # Check the dmidecode output to determine which hardware we're on
  product_string = system_product_name()
  logging.info("Product String: {}".format(product_string))

  if not product_string in firmware_data.keys():
    logging.error("no matching hardware profile for {}".format(product_string))
    sys.exit(2)

  print(firmware_data[product_string]['SYSTEM']['fwpkg'])

  
  #current = survey_host_firmware()
  current = HostFirmware()
  #intel_nic_models = [ m['model'] for m in current['nics']['intel'] ]

  
  #available = available_firmware_versions(firmware_data[product_string], intel_nic_models)
  available = HostFirmware(firmware_data[product_string])

  print("available.system[{}]: {}".format(type(available.system), available.system))
  if opts.report:
    #print(current)
    #print(available)
    report_json(current, available)
    sys.exit(0)

  
  # create/update hp-spp yum repo file

  # update utility packages (if necessary)
  # - gen9 - hp-health package -> 10.90

  # get firmware packages

  # install firmware packages
