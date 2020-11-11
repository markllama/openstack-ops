#!/bin/env python
from __future__ import print_function

import json
import os
import re
import subprocess
import types
import urllib
import urlparse
import yaml

base_url = "http://d490e1c1b2bc716e2eaf-63689fefdb0190e2db0220301cd1330e.r14.cf5.rackcdn.com/"

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

# 
# ILOM
# BIOS
# RAID
# Nics
#   broadcom (single)
#   intel    (multiple)

class Device(object):
  """
  Define data and operations for system firmware checking and update
  """

  _hw_generations = ('gen8', 'gen9', 'gen10')
  _fw_types = ('ilom', 'bios', 'raid', 'nic')
  
  #_fw_type = None
  #_check_cmd = []

  def __init__(self,
               hw_generation=None,
               match_string=None,
               check_cmd=None,
               check_pattern=None):

    self.hw_generation = hw_generation

    self._current = None
    self.available = None
    
    self.package_file = None
    self.package_checksum = None
    self.repo_base_url = None

  @property
  def fw_type(self):
    return self._fw_type

  @property
  def uptodate(self, actual=None, available=None):
    """
    TBD
    """
    return self.match_string in self.current

  def get_current(self):
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

  @property  
  def current(self):
    """
    TBD
    """
    if self._current == None:
      self._current = self.get_current()

    return self._current

  def fetch_package(self, dest_dir="/var/tmp", base_url=None):
    """
    Get the file, put it in the destination and confirm the checksum
    """
    url = urlparse.urljoin(base_url, self.package_file)
    urllib.urlretrieve(url, filename=os.path.join(dest_dir, self.package_file))
      
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
  _fw_type = "nic"
  _check_pattern = "^firmware-version: (.*)$"
  _check_format = "ethtool -i {}"

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
  

def test():

  sysgen = system_product_name()
  print("System is: {}".format(sysgen))
  
  if os.path.exists("firmware.yaml"):
    available = yaml.load(open("firmware.yaml"))
  else:
    available = None

  # is this a known system type?
  if sysgen not in [ p['name'] for p in available['systems']]:
    print("Unrecognized system: {}".format(sysgen))
    sys.exit(1)

  print("Creating an Ilom Device")
  ilom = IlomDevice(
    # hw_generation="gen9",
    # match_string="2.73"
  )

  ilom.match_string = "2.72"
  ilom.package_file = "hp-firmware-ilo4-2.73-1.1.i386.rpm"
  ilom.package_md5 = "c436f2200c8341cdb4c44899954038bc"

  print("ILOM Device Type = {}".format(ilom.fw_type))
  print("ILOM Current = {}".format(ilom.current))
  print("ILOM up to date: {}".format(ilom.uptodate))

  print("Creating a BIOS Device")
  bios = BiosDevice()
  bios.match_string = "10/21/2019"
  bios.package_file = "hp-firmware-system-p89-2.76_2019_10_21-1.1.i386.rpm"
  bios.package_md5 = "952e3b3244dd818084fbd09cc3f8c14e"
  
  print("BIOS Device Type = {}".format(bios.fw_type))
  print("BIOS Current = {}".format(bios.current))
  print("BIOS up to date: {}".format(bios.uptodate))

  print("Creating a RAID Device")
  raid = RaidDevice()
  raid.match_string = "7.00"
  raid.package_file = "hp-firmware-smartarray-ea3138d8e8-7.00-1.1.x86_64.rpm"
  raid.package_md5 = "84261221942a6dd6bd6898620f460f56"
  
  print("RAID Device Type = {}".format(raid.fw_type))
  print("RAID Current = {}".format(raid.current))
  print("RAID up to date: {}".format(raid.uptodate))


  hardware_nics = NicDevice.get_nic_data(NicDevice.get_nic_devices())
  nics = [ NicDevice(data=n) for n in hardware_nics ]
  #print("NIC Hardware = {}".format(json.dumps([ {"name": n.device, "current": n.current, "model": n.hp_model_number, "subsys": n.pci_device_subsystem} for n in nics], indent=2)))

if __name__ == "__main__":

  
  test()
