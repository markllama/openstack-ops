#!/bin/env python
from __future__ import print_function

import os
import re

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

if __name__ == "__main__":
  print(get_broadcom_nics())

