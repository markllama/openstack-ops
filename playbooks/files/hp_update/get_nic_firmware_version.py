#!/usr/bin/env python
from __future__ import print_function

import subprocess
import sys

def get_nic_firmware_version(nic):
  ethtool_template = 'ethtool -i {}'

  # Execute the ethtool command for the provided NIC
  ethtool_cmd = ethtool_template.format(nic).split()
  ethtool_proc = subprocess.Popen(ethtool_cmd, stdout=subprocess.PIPE)
  (ethtool_output, err_out) = ethtool_proc.communicate()

  # Extract the firmware line
  firmware_line = [ l for l in ethtool_output.split('\n') if l.startswith('firmware')][0]

  # The line has the form: firmware-version: 5719-v1.46 NCSI v1.5.1.0  
  firmware = firmware_line.split()[1:]
  return firmware

if __name__ == "__main__":
  print(get_nic_firmware_version(sys.argv[1]))
