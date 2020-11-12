#!/bin/env python
from __future__ import print_function

import hashlib
import json
import os
import re
import subprocess
import tempfile
import types
import urllib
try:
  import urlparse
except:
  import urllib.parse as urlparse
import yaml

#HPE download repo token for mark.lamourine@rackspace.com
# token = "R3WfOnFgSPkhmL7Df0gT03gtLSZ9HX5euTuPj97O7JuEVmIdQN0Yl-sjYLN4V_BBVy0VTJAShJ6l-5ull6luvg"

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


class Firmware(object):
  """
  This object represents firmware updates that are available.
  It includes data to check against a system device to determine if an
  update is in order and to retrieve and install the firmware.
  """

  base_url = None
  tmp_dir = None

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

  def fetch(self, tmp_dir=None, base_url=None):
    """
    Get the file, put it in the destination and confirm the checksum
    """
    if base_url == None:
      base_url = self.base_url
    if tmp_dir == None:
      tmp_dir = self.tmp_dir
    url = urlparse.urljoin(base_url, self.package_name)
    dest = os.path.join(tmp_dir, self.package_name)
    urllib.urlretrieve(url, filename=dest)

    # check the md5 sum
    chksum = hashlib.md5()
    chksum.update(open(dest).read())

    if chksum.hexdigest() != self.package_md5:
      raise Exception("md5 sum mismatch: actual: {} != expected: {}".format(chksum, self.package_md5))
    

  def install(self):
    """
    """
    pass
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
  
def load_firmwares():
  sysgen = system_product_name()
  print("System is: {}".format(sysgen))
  
  if os.path.exists("firmware.yaml"):
    available = yaml.load(open("firmware.yaml"))
    
    # expand to this later:
    # https://stackoverflow.com/questions/3223604/how-to-create-a-temporary-directory-and-get-the-path-file-name-in-python
    Firmware.tmp_dir = tempfile.mkdtemp()

    # Tell the Firmware objects where to find the RPMs when asked to retrieve
    Firmware.base_url = available['firmware_cache_url']
  else:
    available = None

  # is this a known system type?
  if sysgen not in [ p['name'] for p in available['systems']]:
    print("Unrecognized system: {}".format(sysgen))
    sys.exit(1)

  # This is not really efficient, but lists of things should be lists
  fw_specs = [ s['devices'] for s in available['systems'] if s['name'] == sysgen ][0]
  #print("There are {} firmware specs for {}\n\n{}".format(len(fw_specs), sysgen, fw_specs))

  firmwares = []
  for s in fw_specs:
    fw = Firmware.from_dict(s)
    firmwares.append(fw)

  return firmwares
  
  

def load_devices():

  ilom = IlomDevice()
  bios = BiosDevice()
  raid = RaidDevice()
  hardware_nics = NicDevice.get_nic_data(NicDevice.get_nic_devices())
  nics = [ NicDevice(data=n) for n in hardware_nics ]

  return {'ilom': ilom, 'bios': bios, 'raid': raid, 'nics': nics}

if __name__ == "__main__":

  # expand to this later:
  # https://stackoverflow.com/questions/3223604/how-to-create-a-temporary-directory-and-get-the-path-file-name-in-python
  download_dir = tempfile.mkdtemp()
  
  devices = load_devices()
  firmwares = load_firmwares()

  # should only be one ilom firmware
  ilom_fw = [ifw for ifw in firmwares if ifw.type == 'ilom'][0]
  devices['ilom'].firmware = ilom_fw
  print("ILOM uptodate = {}".format(devices['ilom'].uptodate))
  ilom_fw.fetch()
  
  # find all the bios fw
  bios_fw = [ bfw for bfw in firmwares if bfw.type == 'bios']
  # just pick the first for now
  devices['bios'].firmware = bios_fw[0]
  print("BIOS uptodate = {}".format(devices['ilom'].uptodate))

  # There should be only one raid_fw
  raid_fw = [ rfw for rfw in firmwares if rfw.type == 'raid']
  devices['raid'].firmware = raid_fw[0]
  print("RAID uptodate = {}".format(devices['raid'].uptodate))

  # Create an index for the nic firmwares by driver name
  nic_fw_by_driver = {}
  for nfw in [f for f in firmwares if f.type == 'nic']:
    nic_fw_by_driver[nfw.driver]=nfw

  # match each nic device with a fw for the driver type
  for nd in devices['nics']:
    # find a fw that matches
    nd.firmware = nic_fw_by_driver[nd.driver]
    print("NIC {} ({}) uptodate = {}".format(nd.device, nd.driver, nd.uptodate))

  
