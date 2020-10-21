#!/usr/bin/env python
from __future__ import print_function

import subprocess

def get_raid_firmware_version():

  cmd_string = "ssacli controller all show config detail"

  query = subprocess.Popen(cmd_string.split(), stdout=subprocess.PIPE)
  (response_str, std_out) = query.communicate()

  #version_pattern="^\s+Firmware Version:\s+([^\s]+)$"
  version_line = [ l for l in response_str.split("\n") if "Firmware Version" in l][0]

  return version_line.split(':')[1].strip()

if __name__ == "__main__":
  print(get_raid_firmware_version())
