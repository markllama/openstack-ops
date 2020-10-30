#!/usr/bin/env python
from __future__ import print_function

import json
import os
import re
import subprocess

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

  # you can do this just by checking for the presence of a 'device' subdir
  # Select the nic patterns that are of interest - no VLANs
  #  nic_pattern = re.compile("^(eth|em|eno|ens[0-9]f)[0-9]+$")
  #  nics = [ n for n in nics if nic_pattern.match(n) ]

  nics = [ n for n in nics if os.path.exists('/sys/class/net/{}/device'.format(n)) ]
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

# ============================================================================
# NEW STUFF BELOW
# ============================================================================

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


def pci_slot(network_data):
  """
  TBD
  """
  pci_slot_pattern = "^pci@[0-9a-zA-Z]{4}:([0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}\.\d)"
  pci_slot_re = re.compile(pci_slot_pattern)

  match = pci_slot_re.match(network_data['businfo'])
  
  return str(match.groups()[0])

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


if __name__ == "__main__":

  nics = get_nic_hardware()
  intel_nics = [ n for n in nics if nic_is_intel_10gbe(n) ]
  slots = [pci_slot(n) for n in intel_nics]
  
  print(slots)

  subsystems = [ pci_device_subsystem(s) for s in slots ]
  print(subsystems)

  model_numbers = [ hp_nic_model_number(s) for s in subsystems ]
  print(model_numbers)

  logicalnames = [ str(n['logicalname']) for n in intel_nics ]
  print(logicalnames)

  firmware_revisions = [ get_nic_firmware_version(n) for n in intel_nics ]
  print(firmware_revisions)

  #firmware_map = { l: get_nic_firmware_version(l) for l in logicalnames }
  #print(firmware_map)
  
  nics_by_system = get_nic_devices()
  print(nics_by_system)

  intel_nics_by_system = [ n for n in nics_by_system if get_nic_driver(n) == 'ixgbe']
  print(intel_nics_by_system)
  # map the firmware revision to each nic

  fw_revisions_by_system = [get_nic_firmware_version(n) for n in intel_nics_by_system ]
  print(fw_revisions_by_system)

  
