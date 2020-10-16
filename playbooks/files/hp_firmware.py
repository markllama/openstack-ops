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

import json
import platform
import re
import os


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
  return "Red Hat Enterprise Linux Server" in platform.linux.distribution()

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

# ========================================================================
# MAIN
# ========================================================================
if __name__ == "__main__":
  nics = get_broadcom_nics()
  firmware_specs = load_firmware_data("firmware_list.json")
