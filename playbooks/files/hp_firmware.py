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

import atexit
import hashlib
import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import urllib
try:
  import urlparse
except:
  import urllib.parse as urlparse
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
    "ipmitool",
    "lshw",
    "pciutils",
    "pexpect"
  ],
  'hp': [
    "hp-health",
    "hponcfg",
    "ssacli"
  ]
}

# ------------------------------------------------------------------------
# CLI Argument Processing
# ------------------------------------------------------------------------
#
# -D --firmware-data - A JSON file containing the firmware definitions for updates
#    default: ./firmware_data.yaml
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

def update_redhat_packages(packages=[], enablerepo=None):
  """
  Install or update a set of packages provided.
  """

  if enablerepo != None:
    yum_options = "--enablerepo " + enablerepo
  else:
    yum_options = ""
  cmd_template = "/bin/env yum -y {} install {}"
  cmd_string = cmd_template.format(yum_options, " ".join(packages))
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

  package_status = package_versions(requirements['redhat'])
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
    
  package_status = package_versions(requirements['hp'])
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
  
  # I should have some better response
  if p.returncode != 0:
    response = "Family Model Generation"

  return response.strip()


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

# ===========================================================================
# ===========================================================================
# Firmware Object
# ===========================================================================
# ===========================================================================

class Firmware(object):
  """
  This object represents firmware updates that are available.
  It includes data to check against a system device to determine if an
  update is in order and to retrieve and install the firmware.
  """

  base_url = None
  tmp_dir = None

  # -------------------------------------------------------------------------
  # Firmware Constructors
  # -------------------------------------------------------------------------
  
  def __init__(self,
               name=None,
               fw_type=None,
               driver=None,
               versions=[],
               package_name=None,
               package_md5=None):

    self.name = name
    self.type = fw_type
    self.driver = driver
    self.versions = versions
    self.package_name = package_name
    self.package_md5 = package_md5

  @staticmethod
  def from_dict(structure):
    """
    Create a Firmware object from a dictionary loaded from YAML or JSON
    """
    keys = structure.keys()
    f = Firmware()
    f.name = structure['name'] if 'name' in keys else None
    f.type = structure['type'] if 'type' in keys else None
    f.driver = structure['driver'] if 'driver' in keys else None
    if 'package' in keys:
      f.package_name = structure['package']['name']
      f.package_md5 = structure['package']['md5']
    else:
      f.package_name = None
      f.package_md5 = None
    f.versions = structure['versions'] if 'versions' in keys else []
    f.name = structure['name'] if 'name' in keys else None

    return f

  # --------------------------------------------------------------------------
  # Firmware properties
  # --------------------------------------------------------------------------
  
  @property
  def package_file(self):
    return os.path.join(self._package_dir, self.package_name)

  @property
  def _package_dir(self):
    pd = os.path.join(self.tmp_dir, 'rpms')
    if not os.path.exists(pd):
      os.mkdir(pd)
    return pd

  @property
  def _unpack_root(self):
    ur = os.path.join(self.tmp_dir, 'unpack')
    if not os.path.exists(ur):
      os.mkdir(ur)
    return ur

  @property
  def _unpack_dir(self):
    ud = os.path.join(self._unpack_root, self.package_name)
    if not os.path.exists(ud):
      os.mkdir(ud)
    return ud

  # -------------------------------------------------------------------------
  # Firmware Methods
  # -------------------------------------------------------------------------

  def fetch(self, dest_dir=None, base_url=None):
    """
    Get the file, put it in the destination and confirm the checksum
    """

    # If the caller gave a value it overrides the default location
    if base_url == None:
      base_url = self.base_url
    url = urlparse.urljoin(base_url, self.package_name)

    urllib.urlretrieve(url, filename=self.package_file)

    # generate the md5 sum of the downloaded file
    chksum = hashlib.md5()
    pkgfile = open(self.package_file)
    chksum.update(pkgfile.read())
    pkgfile.close()

    # Verify that the file matches expectation
    if chksum.hexdigest() != self.package_md5:
      raise Exception("md5 sum mismatch: actual: {} != expected: {}".format(chksum, self.package_md5))
    
    return self.package_file

  def unpack(self, unpack_dir=None):
    """
    Unpack a downloaded firmware RPM into a local directory
    """

    cwd = os.getcwd()
    os.chdir(self._unpack_dir)
    convert_cmd = 'rpm2cpio ' + self.package_file
    unpack_cmd = 'cpio --extract --quiet --make-directories ' + self._unpack_dir
    convert = subprocess.Popen(convert_cmd.split(), stdout=subprocess.PIPE)
    unpack = subprocess.check_output(unpack_cmd.split(), stdin=convert.stdout)
    os.chdir(cwd)

    return self._unpack_dir

  def install(self, unpack_dir=None):
    """
    Install an HP firmware update from an unpacked RPM
    """

  # expect
  #   <path>/hpsetup
  #
  #   expect("Continue (y/N)?")
  #   sendline("y")
  #   expect("Succeded.")
  #   expect("iLO 4 reboot completed.")
  

    pass

def load_firmwares(firmware_data_file):
  sysgen = system_product_name()
  logging.info("System is: {}".format(sysgen))
  
  if os.path.exists(firmware_data_file):
    logging.debug("Loading {}".format(firmware_data_file))
    available = yaml.load(open(firmware_data_file))
    
    # expand to this later:
    # https://stackoverflow.com/questions/3223604/how-to-create-a-temporary-directory-and-get-the-path-file-name-in-python
    Firmware.tmp_dir = tempfile.mkdtemp()

    # Tell the Firmware objects where to find the RPMs when asked to retrieve
    Firmware.base_url = available['firmware_cache_url']
  else:
    available = None

  # is this a known system type?
  if str(sysgen) not in [ str(p['name']) for p in available['systems']]:
    print("Unrecognized system: '{}'".format(str(sysgen)))
    print("Available = {}".format([ p['name'] for p in available['systems']]))
    sys.exit(1)

  # This is not really efficient, but lists of things should be lists
  fw_specs = [ s['devices'] for s in available['systems'] if s['name'] == sysgen ][0]
  #print("There are {} firmware specs for {}\n\n{}".format(len(fw_specs), sysgen, fw_specs))

  firmwares = []
  for s in fw_specs:
    fw = Firmware.from_dict(s)
    firmwares.append(fw)

  return firmwares

# ---------------------------------------------------------------------------
# Device Class
# ---------------------------------------------------------------------------

# 
# ILOM
# BIOS
# RAID
# NICS

class Device(object):
  """
  Define data and operations for system firmware checking and update
  This is an semi-abstract(ish) base class for the real devices
  """

  _hw_generations = ('gen8', 'gen9', 'gen10')
  _fw_types = ('ilom', 'bios', 'raid', 'nic')
  
  #_fw_type = None
  #_check_cmd = []

  def __init__(self):
    self._current = None
    self.available = None
    self.firmware = None

  @property
  def uptodate(self, actual=None, available=None):
    """
    TBD
    """
    if self.firmware == None:
      return None

    if len(self.firmware.versions) == 1:
      match_string = self.firmware.versions[0]['match_string']
    else:
      return True

    return match_string in self.current

  @property  
  def current(self):
    """
    TBD
    """
    if self._current == None:
      self._current = self._get_current()

    return self._current

  def _get_current(self):
    p = subprocess.Popen(self._check_cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (response, stderr) = p.communicate()

    firmware_re = re.compile(self._check_pattern)

    fw_version = None
    for line in response.split('\n'):
      match = firmware_re.match(line)
      if match:
        fw_version = match.groups()[0]
        break

    return fw_version

# ---------------------------------------------------------------------------
# Concrete Device Classes
# ---------------------------------------------------------------------------
# These classes represent the system devices that need firmware updates

class IlomDevice(Device):

  _fw_type = "ilom"
  _check_pattern = "^Firmware Revision = (\d+\.\d+) "
  _check_cmd = "hponcfg -h".split()
  
  def __init__(self):
    super(IlomDevice, self).__init__()


class BiosDevice(Device):
  _fw_type = "bios"
  _check_pattern = "ROM version\s*:\s(.*)$"
  _check_cmd =  ['hpasmcli', '-s',  'show server']

  def __init__(self):
    super(BiosDevice, self).__init__()


class RaidDevice(Device):
  _fw_type = "raid"
  _check_pattern = "^\s*Firmware Version: (.*)$"
  _check_cmd = "ssacli controller all show config detail".split()

  def __init__(self):
    super(RaidDevice, self).__init__()


class NicDevice(Device):
  """
  The NIC class is the most detailed because there can be many NICs and they
  can use different drivers and firmware.
  """
  _fw_type = "nic"
  _check_pattern = "^firmware-version: (.*)$"
  _check_format = "ethtool -i {}"

  # ----------------------
  # NIC Device Constructor
  # ----------------------
  
  def __init__(self, device=None, data=None):
    """
    Nic checks require a device
    """
    super(NicDevice, self).__init__()
    self.data = data
    if device != None:
      self.device = device
    elif self.data != None:
      self.device = data['logicalname']

  # --------------------------
  # NIC Device Static Methods:
  # --------------------------
  # These methods gather the list of NICs on a system and make queries
  # These run against the entire system to determine the set of NIC
  # devices to be examined.
  
  @staticmethod
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

  @staticmethod
  def get_nic_data(nics=None):
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

    # Filter for just the nics requested
    if type(nics) == types.StringType:
      networks = [ networks[nics] ]
    elif type(nics) == types.ListType:
      networks = [ n for n in networks if n['logicalname'] in nics ]

    return networks

  # -------------------
  # NIC Device Properties
  # -------------------
  # These methods define dynamic values that are retrieved for each NIC
  # on demand
  
  @property
  def _check_cmd(self):
    """
    TBD
    """
    return self._check_format.format(self.device).split()

  @property
  def driver(self):
    """
    Return the driver module used by a giving nic device
    """
    driver_name = None

    dev_file = open("/sys/class/net/{}/device/uevent".format(self.device),"r")
    # Only change the value if you find it
    for line in dev_file:
      if "DRIVER=" in line:
        driver_name = line.strip().split('=')[1]
        break
    dev_file.close()

    return driver_name

  @property
  def pci_slot(self):
    """
    TBD
    """
    pci_slot_pattern = "^pci@[0-9a-zA-Z]{4}:([0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}\.\d)"
    pci_slot_re = re.compile(pci_slot_pattern)

    match = pci_slot_re.match(self.data['businfo'])
  
    return str(match.groups()[0])

  @property
  def pci_device_subsystem(self):
    """
    TBD
    """
    lspci_cmd_str = "lspci -v -s {}"

    p = subprocess.Popen(lspci_cmd_str.format(self.pci_slot).split(),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (response, stderr) = p.communicate()

    for line in response.split("\n"):
      if "Subsystem:" in line:
        return line.split(":")[1].strip()

    return None

  @property
  def hp_model_number(self):
    """
    TBD
    """
    # This is an odd looking pattern:
    #   It matches a set of HP model numbers
    #     
    model_pattern = '[3,5][6][0-9][A-Z,i]{1,3}-?[A-Z]{0,5}\+?'
    match = re.search(model_pattern, self.pci_device_subsystem)

    return None if match == None else match.group(0)


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
      key = str(key.encode('utf-8'))
    if isinstance(value, unicode):
      value = str(value.decode('utf-8'))
    elif isinstance(value, list):
      value = str(_decode_list(value))
    elif isinstance(value, dict):
      value = str(_decode_dict(value))
    rv[key] = value
  return rv
  

def load_devices():

  ilom = IlomDevice()
  bios = BiosDevice()
  raid = RaidDevice()
  hardware_nics = NicDevice.get_nic_data(NicDevice.get_nic_devices())
  nics = [ NicDevice(data=n) for n in hardware_nics ]

  return {'ilom': ilom, 'bios': bios, 'raid': raid, 'nics': nics}

def _cleanup(tmp_dir=None):
  """
  This function removes the working directory on exit
  """
  if tmp_dir != None and os.path.exists(tmp_dir):
    shutil.rmtree(tmp_dir)
    

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

  # expand to this later:
  # https://stackoverflow.com/questions/3223604/how-to-create-a-temporary-directory-and-get-the-path-file-name-in-python
  working_dir = tempfile.mkdtemp()
  logging.info("Working directory = {}".format(working_dir))
  Firmware.tmp_dir = working_dir

  # make sure to clean up when you're done
  atexit.register(_cleanup, tmp_dir=working_dir)
  
  devices = load_devices()
  firmwares = load_firmwares(opts.firmware_data)
